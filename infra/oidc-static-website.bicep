@description('Globally unique name for the static website storage account.')
param storageAccountName string

@description('Azure region for the storage account.')
param location string = resourceGroup().location

@description('Tags applied to the storage account.')
param tags object = {}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  tags: tags
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

// staticWebsite was added to the Blob service resource schema in the newer
// Storage RP API. Older API versions can translate this object to
// `staticWebsiteEnabled`, which the service rejects as an invalid property.
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2025-08-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    staticWebsite: {
      enabled: true
      indexDocument: 'index.html'
    }
  }
}

output staticWebsiteUrl string = storageAccount.properties.primaryEndpoints.web
