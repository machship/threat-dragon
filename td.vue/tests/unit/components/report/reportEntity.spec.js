import { BootstrapVue, BTable } from 'bootstrap-vue';
import { shallowMount, createLocalVue } from '@vue/test-utils';

import TdReportEntity from '@/components/report/ReportEntity.vue';

describe('components/report/ReportEntity.vue', () => {
    let propsData, wrapper;

    const getData = () => ({
        outOfScope: false,
        entity: {
            data: {
                name: 'Some threat',
                type: 'td.Actor',
                description: 'Some actor doing some things',
                threats: [
                    {
                        number: '1',
                        title: 't1',
                        severity: 'High',
                        score: 'score10',
                        status: 'Open',
                        type: 'type1',
                        description: 'Threat 1',
                        mitigation: 'We have yet to do things'
                    },
                    {
                        number: '2',
                        title: 't2',
                        severity: 'Medium',
                        score: 'score5',
                        status: 'Mitigated',
                        type: 'type2',
                        description: 'Threat 2',
                        mitigation: 'We did things'
                    },
                    {
                        number: '3',
                        title: 't3',
                        severity: 'Low',
                        score: 'score1',
                        status: 'NotApplicable',
                        type: 'type3',
                        description: 'Threat 3',
                        mitigation: 'No need to do things'
                    }
                ]
            }
        }
    });

    const setup = (data) => {
        const localVue = createLocalVue();
        localVue.use(BootstrapVue);
        wrapper = shallowMount(TdReportEntity, {
            localVue,
            propsData: {
                outOfScope: data.outOfScope,
                entity: data.entity
            },
            mocks: {
                $t: t => t
            }
        });
    };

    describe('in scope', () => {
        beforeEach(() => {
            propsData = getData();
            setup(propsData);
        });
    
        it('converts things to camel case', () => {
            expect(wrapper.vm.toCamelCase('FooBar')).toEqual('fooBar');
        });
    
        it('displays the name and data type', () => {
            expect(wrapper.find('.entity-title').text())
                .toEqual(`${propsData.entity.data.name} (threatmodel.shapes.actor)`);
        });
    
        it('displays the entity description', () => {
            expect(wrapper.find('.entity-description').text())
                .toContain(propsData.entity.data.description);
        });
        
        it('has a table with the threats', () => {
            expect(wrapper.findComponent(BTable).exists())
                .toEqual(true);
        });
    });

    describe('out of scope', () => {
        beforeEach(() => {
            propsData = getData();
            propsData.outOfScope = true;
            setup(propsData);
        });

        it('has a table with the threats', () => {
            expect(wrapper.findComponent(BTable).exists())
                .toEqual(true);
        });
    });

    describe('formatType', () => {
        beforeEach(() => {
            setup(getData());
        });

        it('returns the type when there is no ASI', () => {
            expect(wrapper.vm.formatType({ type: 'Cross-layer' })).toEqual('Cross-layer');
        });

        it('appends the ASI to the type', () => {
            expect(wrapper.vm.formatType({ type: 'Cross-layer', modelType: 'MAESTRO', asi: 'ASI08' })).toEqual('Cross-layer (ASI08)');
        });

        it('ignores an ASI on a non-MAESTRO threat', () => {
            expect(wrapper.vm.formatType({ type: 'Spoofing', modelType: 'STRIDE', asi: 'ASI08' })).toEqual('Spoofing');
        });

        it('shows the ASI in the table data', () => {
            const data = getData();
            data.entity.data.threats[0].modelType = 'MAESTRO';
            data.entity.data.threats[0].asi = 'ASI02';
            setup(data);
            expect(wrapper.vm.tableData[0]['threats.properties.type']).toEqual('type1 (ASI02)');
        });
    });

    describe('translateStatus', () => {
        beforeEach(() => {
            setup(getData());
        });

        it('translates the accepted status', () => {
            expect(wrapper.vm.translateStatus('Accepted')).toEqual('threats.status.accepted');
        });

        it('translates the transferred status', () => {
            expect(wrapper.vm.translateStatus('Transferred')).toEqual('threats.status.transferred');
        });

        it('translates the avoided status', () => {
            expect(wrapper.vm.translateStatus('Avoided')).toEqual('threats.status.avoided');
        });

        it('translates eliminated status', () => {
            expect(wrapper.vm.translateStatus('Eliminated')).toEqual('threats.status.eliminated');
        });

        it('falls back to Unknown for an unrecognised status', () => {
            expect(wrapper.vm.translateStatus('Bogus')).toEqual('Unknown');
        });
    });
});
