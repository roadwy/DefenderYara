
rule Trojan_Win32_SuspAdSyncAccess_A_EntraConnect{
	meta:
		description = "Trojan:Win32/SuspAdSyncAccess.A!EntraConnect,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //05 00  powershell
		$a_00_1 = {6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 6d 00 65 00 74 00 61 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 2e 00 63 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 2e 00 6b 00 65 00 79 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //05 00  microsoft.directoryservices.metadirectoryservices.cryptography.keymanager
		$a_00_2 = {2e 00 6c 00 6f 00 61 00 64 00 6b 00 65 00 79 00 73 00 65 00 74 00 28 00 } //00 00  .loadkeyset(
	condition:
		any of ($a_*)
 
}