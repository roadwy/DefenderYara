
rule Trojan_Win64_Rozena_AF_MTB{
	meta:
		description = "Trojan:Win64/Rozena.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 03 00 "
		
	strings :
		$a_80_0 = {44 6c 6c 36 2e 64 6c 6c } //Dll6.dll  03 00 
		$a_80_1 = {64 69 72 74 72 65 65 5f } //dirtree_  03 00 
		$a_80_2 = {63 3a 2f 62 69 6e 64 61 74 61 } //c:/bindata  03 00 
		$a_80_3 = {53 6f 66 74 77 61 72 65 5c 53 69 6c 76 65 72 53 70 61 63 65 73 68 69 70 5c 73 74 62 } //Software\SilverSpaceship\stb  03 00 
		$a_80_4 = {25 73 2f 25 73 2e 63 66 67 } //%s/%s.cfg  03 00 
		$a_80_5 = {54 62 44 69 52 74 52 65 45 30 32 } //TbDiRtReE02  03 00 
		$a_80_6 = {25 73 20 74 6f 20 63 6f 6e 76 65 72 74 20 27 25 53 27 20 74 6f 20 25 73 21 } //%s to convert '%S' to %s!  03 00 
		$a_80_7 = {4c 6f 63 61 6c 65 4e 61 6d 65 54 6f 4c 43 49 44 } //LocaleNameToLCID  03 00 
		$a_80_8 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //AppPolicyGetProcessTerminationMethod  00 00 
	condition:
		any of ($a_*)
 
}