
rule Trojan_Win32_Tnega_RM_MTB{
	meta:
		description = "Trojan:Win32/Tnega.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 00 03 c6 0f b7 0b 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10 } //1
		$a_03_1 = {8b 54 24 04 8b 52 28 8b c6 03 d0 89 15 ?? ?? ?? ?? 6a 00 6a 01 50 ff 15 90 1b 00 90 0a 3f 00 90 90 90 90 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}