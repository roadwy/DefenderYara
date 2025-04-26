
rule Trojan_Win32_Zenpak_ASAU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 55 fb 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 } //2
		$a_01_1 = {50 8a 45 0c 8a 4d 08 31 d2 88 d4 88 45 fb 88 4d fa } //2
		$a_01_2 = {01 f2 88 d0 a2 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}