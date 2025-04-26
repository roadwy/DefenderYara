
rule Trojan_Win32_Boaxxe_F{
	meta:
		description = "Trojan:Win32/Boaxxe.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 09 89 d0 31 07 83 c7 04 e2 f9 } //1
		$a_01_1 = {61 6a 00 68 6f 75 6e 74 } //1 橡栀畯瑮
		$a_03_2 = {3d 2e 54 4d 50 0f 85 ?? ?? ?? ?? 68 78 41 00 00 } //1
		$a_01_3 = {8b 86 cc 00 00 00 89 c2 e8 00 00 00 00 58 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2) >=3
 
}