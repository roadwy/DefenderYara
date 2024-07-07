
rule Trojan_Win32_Zbot_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {12 29 42 fe 0c 66 30 dd 61 79 } //5
		$a_03_1 = {80 40 88 44 11 80 90 01 04 30 40 00 44 22 90 00 } //5
		$a_01_2 = {40 67 75 5f 69 64 61 74 61 } //1 @gu_idata
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}