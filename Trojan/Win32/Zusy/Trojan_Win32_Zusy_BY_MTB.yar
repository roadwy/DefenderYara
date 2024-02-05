
rule Trojan_Win32_Zusy_BY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {4b 6a 69 61 6a 66 67 69 61 65 67 68 64 61 69 68 } //03 00 
		$a_01_1 = {4e 61 65 75 69 67 6f 68 61 65 67 69 68 64 64 } //01 00 
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}