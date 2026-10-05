const importMaestroModel = () => {
    cy.get('#local-login-btn').click();
    cy.get('a[href="#/local/threatmodel/import"]').click();
    cy.fixture('v2-maestro-model').then((model) => {
        cy.get('#json-input').type(JSON.stringify(model), { parseSpecialCharSequences: false, delay: 0 });
    });
    cy.get('#td-import-btn').click();
    cy.url().should('contain', '/local/MAESTRO%20Threat%20Model');
};

const openOrchestratorThreat = () => {
    cy.contains('.diagram-edit', 'Agent Gateway').click();
    cy.get('#graph-container').should('be.visible');
    cy.contains('#graph-container .x6-cell.x6-node tspan', 'Agent Orchestrator')
        .parents('g.x6-node')
        .first()
        .click({ force: true });
    cy.contains('.threat-card a', 'Poisoned agent memory').click();
};

describe('MAESTRO methodology', () => {
    beforeEach(() => {
        cy.launchThreatDragon();
    });

    it('offers MAESTRO as a diagram type', () => {
        cy.get('#local-login-btn').click();
        cy.get('a[href="#/local/threatmodel/new"]').click();
        cy.get('.add-diagram-link').click();
        cy.get('#diagram-group-0 .td-dropdown-toggle').click();
        cy.get('#diagram-group-0 .td-dropdown-item').contains('MAESTRO').click();
        cy.get('#diagram-group-0 .td-dropdown-toggle').should('contain', 'MAESTRO');
    });

    it('shows the ASI on the threat card', () => {
        importMaestroModel();
        cy.contains('.diagram-edit', 'Agent Gateway').click();
        cy.contains('#graph-container .x6-cell.x6-node tspan', 'Agent Orchestrator')
            .parents('g.x6-node')
            .first()
            .click({ force: true });
        cy.contains('.threat-card', 'Poisoned agent memory').should('contain', 'ASI06');
    });

    it('shows the saved ASI in the threat dialog', () => {
        importMaestroModel();
        openOrchestratorThreat();
        cy.get('#threat-asi option:selected').should('contain', 'ASI06');
    });

    it('offers the MAESTRO layers for a process', () => {
        importMaestroModel();
        openOrchestratorThreat();
        cy.get('#threat-type option').should('contain', 'L1 – Foundation models');
    });

    it('updates the ASI from the threat dialog', () => {
        importMaestroModel();
        openOrchestratorThreat();
        cy.get('#threat-asi').select('ASI02: Tool Misuse and Exploitation', { force: true });
        cy.get('.modal.show').contains('button', 'Apply').click();
        cy.contains('.threat-card', 'Poisoned agent memory').should('contain', 'ASI02');
    });

    it('shows the ASI in the report', () => {
        importMaestroModel();
        cy.get('#td-report-btn').trigger('click');
        cy.get('[data-test-id="Agent_Orchestrator"]').should('contain', 'L3 – Agent frameworks (ASI06)');
    });
});
