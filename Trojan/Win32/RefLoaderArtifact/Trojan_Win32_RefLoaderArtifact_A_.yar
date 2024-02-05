
rule Trojan_Win32_RefLoaderArtifact_A_{
	meta:
		description = "Trojan:Win32/RefLoaderArtifact.A!!RefLoaderArtifact.A,SIGNATURE_TYPE_ARHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec 74 90 01 04 aa fc 0d 7c 74 90 00 } //01 00 
		$a_03_1 = {8e 4e 0e ec 74 90 01 02 aa fc 0d 7c 74 90 00 } //05 00 
	condition:
		any of ($a_*)
 
}