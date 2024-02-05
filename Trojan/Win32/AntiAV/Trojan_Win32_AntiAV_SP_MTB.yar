
rule Trojan_Win32_AntiAV_SP_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 4c 47 42 43 41 4f 2e } //01 00 
		$a_01_1 = {61 6d 64 6b 38 44 65 76 69 63 65 } //01 00 
		$a_01_2 = {63 63 74 65 31 73 74 6f } //01 00 
		$a_01_3 = {61 6d 64 6b 38 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}