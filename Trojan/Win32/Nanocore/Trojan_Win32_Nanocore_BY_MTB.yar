
rule Trojan_Win32_Nanocore_BY_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff ff 5e 8b 0c 1f 53 bb 90 01 04 81 fb 90 1b 00 0f 85 90 01 02 ff ff 5b 68 90 01 04 68 90 1b 03 83 c4 08 16 17 eb 1a 90 00 } //01 00 
		$a_02_1 = {f7 ff ff 5b 4b 90 02 05 8b 17 90 02 05 31 da 90 02 06 39 ca 75 90 01 01 90 02 05 6a 90 01 01 6a 90 1b 05 83 c4 08 16 17 eb 1a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}