
rule Trojan_Win32_Fauppod_MK_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 50 72 6f } //3 OnePro
		$a_01_1 = {54 77 6f 50 72 6f } //3 TwoPro
		$a_01_2 = {54 68 72 50 72 6f } //3 ThrPro
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=10
 
}