import models from '@/service/threats/models';

describe('service/threats/models/index.js', () => {

    describe('allModels', () => {
        it('defines a mdel array', () => {
            expect(models.allModels).toBeInstanceOf(Array);
        });

        it('defines model types', () => {
            expect(models.allModels.includes('CIA')).toBe(true);
            expect(models.allModels.includes('CIADIE')).toBe(true);
            expect(models.allModels.includes('LINDDUN')).toBe(true);
            expect(models.allModels.includes('MAESTRO')).toBe(true);
            expect(models.allModels.includes('PLOT4ai')).toBe(true);
            expect(models.allModels.includes('STRIDE')).toBe(true);
            expect(models.allModels.includes('EOP')).toBe(true);
        });
    });

    describe('asiIds', () => {
        it('defines the ten OWASP Agentic Top 10 IDs', () => {
            expect(models.asiIds).toHaveLength(10);
        });

        it('starts at ASI01', () => {
            expect(models.asiIds[0]).toEqual('ASI01');
        });

        it('ends at ASI10', () => {
            expect(models.asiIds[9]).toEqual('ASI10');
        });
    });

    describe('getByTranslationValue', () => {

        it('identifies a CIA threat', () => {
            expect(models.getByTranslationValue('threats.model.cia.confidentiality'))
                .toEqual('CIA');
        });

        it('identifies a CIA-DIE threat', () => {
            expect(models.getByTranslationValue('threats.model.ciadie.immutable'))
                .toEqual('CIADIE');
        });

        it('identifies a LINDDUN threat', () => {
            expect(models.getByTranslationValue('threats.model.linddun.linkability'))
                .toEqual('LINDDUN');
        });

        it('identifies a MAESTRO threat', () => {
            expect(models.getByTranslationValue('threats.model.maestro.crossLayer'))
                .toEqual('MAESTRO');
        });

        it('identifies a PLOT4ai threat', () => {
            expect(models.getByTranslationValue('threats.model.plot4ai.safety'))
                .toEqual('PLOT4ai');
        });

        it('identifies a STRIDE threat', () => {
            expect(models.getByTranslationValue('threats.model.stride.tampering'))
                .toEqual('STRIDE');
        });

        it('returns an empty string for an unknown type', () => {
            expect(models.getByTranslationValue('threats.models.fake'))
                .toEqual('');
        });

        it('returns an empty string for an undefined type', () => {
            expect(models.getByTranslationValue())
                .toEqual('');
        });
    });

    describe('getThreatTypesByElement', () => {

        it('gets the CIA Actor threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('CIA', 'tm.Actor'))).toHaveLength(3);
        });

        it('gets the CIA Process threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('CIA', 'tm.Process'))).toHaveLength(3);
        });

        it('gets the CIA Store threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('CIA', 'tm.Store'))).toHaveLength(3);
        });

        it('gets the CIA DataFlow threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('CIA', 'tm.Flow'))).toHaveLength(3);
        });

        it('gets the legacy DIE threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('DIE', ''))).toHaveLength(6);
        });

        it('gets the CIA-DIE Actor threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('CIADIE', 'tm.Actor'))).toHaveLength(6);
        });

        it('gets the CIA-DIE Process threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('CIADIE', 'tm.Process'))).toHaveLength(6);
        });

        it('gets the CIA-DIE Store threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('CIADIE', 'tm.Store'))).toHaveLength(6);
        });

        it('gets the CIA-DIE DataFlow threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('CIADIE', 'tm.Flow'))).toHaveLength(6);
        });

        it('gets the LINDDUN Actor threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('linddun', 'tm.Actor'))).toHaveLength(3);
        });

        it('gets the LINDDUN Process threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('linddun', 'tm.Process'))).toHaveLength(6);
        });

        it('gets the LINDDUN Store threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('linddun', 'tm.Store'))).toHaveLength(6);
        });

        it('gets the LINDDUN DataFlow threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('linddun', 'tm.Flow'))).toHaveLength(6);
        });

        it('gets the MAESTRO Actor threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('maestro', 'tm.Actor'))).toHaveLength(3);
        });

        it('gets the MAESTRO Process threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('MAESTRO', 'tm.Process'))).toHaveLength(7);
        });

        it('gets the MAESTRO Store threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('maestro', 'tm.Store'))).toHaveLength(6);
        });

        it('gets the MAESTRO DataFlow threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('maestro', 'tm.Flow'))).toHaveLength(6);
        });

        it('offers the MAESTRO cross-layer type on the actor', () => {
            expect(Object.keys(models.getThreatTypesByElement('MAESTRO', 'tm.Actor')))
                .toContain('threats.model.maestro.crossLayer');
        });

        it('lists the MAESTRO process types in layer order', () => {
            expect(Object.keys(models.getThreatTypesByElement('MAESTRO', 'tm.Process'))[0])
                .toEqual('threats.model.maestro.foundationModels');
        });

        it('gets the PLOT4ai Actor threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('plot4ai', 'tm.Actor'))).toHaveLength(6);
        });

        it('gets the PLOT4ai Process threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('plot4ai', 'tm.Process'))).toHaveLength(5);
        });

        it('gets the PLOT4ai Store threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('plot4ai', 'tm.Store'))).toHaveLength(5);
        });

        it('gets the PLOT4ai DataFlow threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('plot4ai', 'tm.Flow'))).toHaveLength(4);
        });

        it('gets the STRIDE Actor threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('Stride', 'tm.Actor'))).toHaveLength(2);
        });

        it('gets the STRIDE Process threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('Stride', 'tm.Process'))).toHaveLength(6);
        });

        it('gets the STRIDE Store threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('Stride', 'tm.Store'))).toHaveLength(4);
        });

        it('gets the STRIDE DataFlow threat types', () => {
            expect(Object.keys(models.getThreatTypesByElement('Stride', 'tm.Flow'))).toHaveLength(3);
        });

        it('returns all threat types when the model type is not found', () => {
            console.error = jest.fn();
            expect(Object.keys(models.getThreatTypesByElement('fake', 'tm.Actor'))).toHaveLength(44);
        });

        it('uses the CIADIE header translation key for an unknown model type', () => {
            const threatTypes = models.getThreatTypesByElement('fake', 'tm.Actor');

            expect(threatTypes['threats.model.ciadie.header']).toBe('ciaDieHeader');
        });
    });

    describe('getFrequencyMapByElement', () => {

        it('gets the CIA Actor map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('CIA', 'tm.Actor'))).toHaveLength(3);
        });

        it('gets the CIA Process map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('CIA', 'tm.Process'))).toHaveLength(3);
        });

        it('gets the CIA Store map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('cia', 'tm.Store'))).toHaveLength(3);
        });

        it('gets the CIA Flow map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('cia', 'tm.Flow'))).toHaveLength(3);
        });

        it('gets the legacy DIE map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('DIE', ''))).toHaveLength(6);
        });

        it('gets the CIADIE Actor map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('CIADIE', 'tm.Actor'))).toHaveLength(6);
        });

        it('gets the CIADIE Process map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('CIADIE', 'tm.Process'))).toHaveLength(6);
        });

        it('gets the CIADIE Store map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('ciadie', 'tm.Store'))).toHaveLength(6);
        });

        it('gets the CIADIE Flow map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('ciadie', 'tm.Flow'))).toHaveLength(6);
        });

        it('gets the LINDDUN Actor map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('LINDDUN', 'tm.Actor'))).toHaveLength(3);
        });

        it('gets the LINDDUN Process map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('LINDDUN', 'tm.Process'))).toHaveLength(6);
        });

        it('gets the LINDDUN Store map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('linddun', 'tm.Store'))).toHaveLength(6);
        });

        it('gets the LINDDUN Flow map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('linddun', 'tm.Flow'))).toHaveLength(6);
        });

        it('gets the MAESTRO Actor map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('MAESTRO', 'tm.Actor'))).toHaveLength(3);
        });

        it('gets the MAESTRO Process map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('maestro', 'tm.Process'))).toHaveLength(7);
        });

        it('gets the MAESTRO Store map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('maestro', 'tm.Store'))).toHaveLength(6);
        });

        it('gets the MAESTRO Flow map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('maestro', 'tm.Flow'))).toHaveLength(6);
        });

        it('provides a MAESTRO default map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('maestro', 'foobar'))).toHaveLength(6);
        });

        it('starts the MAESTRO map at zero', () => {
            expect(models.getFrequencyMapByElement('MAESTRO', 'tm.Actor').crossLayer).toEqual(0);
        });

        it('gets the PLOT4ai Actor map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('PLOT4ai', 'tm.Actor'))).toHaveLength(6);
        });

        it('gets the PLOT4ai Process map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('PLOT4AI', 'tm.Process'))).toHaveLength(5);
        });

        it('gets the PLOT4ai Store map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('plot4ai', 'tm.Store'))).toHaveLength(5);
        });

        it('gets the PLOT4ai Flow map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('plot4ai', 'tm.Flow'))).toHaveLength(4);
        });

        it('provides a PLOT4ai default map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('plot4ai', 'foobar'))).toHaveLength(4);
        });

        it('gets the STRIDE Actor map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('STRIDE', 'tm.Actor'))).toHaveLength(2);
        });

        it('gets the STRIDE Process map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('STRIDE', 'tm.Process'))).toHaveLength(6);
        });

        it('gets the STRIDE Store map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('stride', 'tm.Store'))).toHaveLength(4);
        });

        it('gets the STRIDE Flow map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('stride', 'tm.Flow'))).toHaveLength(3);
        });

        it('provides a STRIDE default map', () => {
            expect(Object.keys(models.getFrequencyMapByElement('stride', 'foobar'))).toHaveLength(3);
        });

        it('handles unknown model type', () => {
            expect(models.getFrequencyMapByElement('fake', 'tm.Actor')).toBeNull();
        });
    });
});
