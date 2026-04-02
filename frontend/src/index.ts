import { faGlobe } from '@fortawesome/free-solid-svg-icons';
import { Extension, ExtensionContext } from 'shared';
import AdminSubdomainManagerPage from './pages/AdminSubdomainManagerPage.tsx';
import ServerSubdomainPage from './pages/ServerSubdomainPage.tsx';

class DevLuxxyCloudflareSubdomainExtension extends Extension {
  public cardConfigurationPage: React.FC | null = AdminSubdomainManagerPage;
  public cardComponent: React.FC | null = null;

  public initialize(ctx: ExtensionContext): void {
    ctx.extensionRegistry.routes.addServerRoute({
      name: 'Subdomain',
      icon: faGlobe,
      path: '/subdomain',
      element: ServerSubdomainPage,
      permission: 'allocations.read',
    });
  }
}

export default new DevLuxxyCloudflareSubdomainExtension();
