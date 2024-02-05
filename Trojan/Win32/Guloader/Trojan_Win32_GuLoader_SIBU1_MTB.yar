
rule Trojan_Win32_GuLoader_SIBU1_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBU1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 4f 4c 44 49 45 52 49 4e 47 20 53 65 74 75 70 3a 20 49 6e 73 74 61 6c 6c 69 6e 67 } //01 00 
		$a_03_1 = {f9 81 34 1a 90 01 04 90 02 35 43 90 02 30 43 90 02 3a 43 90 02 30 43 90 02 3a 81 fb 90 01 04 90 02 40 0f 85 90 01 04 90 08 3a 01 81 36 90 01 04 90 02 40 81 2e 90 01 04 90 02 3a ff d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}