
rule Trojan_Win32_Starter_CCJK_MTB{
	meta:
		description = "Trojan:Win32/Starter.CCJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 89 44 24 04 8b 45 e0 89 04 24 e8 dc 94 01 } //5
		$a_01_1 = {c7 44 24 14 01 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 89 44 24 08 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 cc 91 01 } //6
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*6) >=11
 
}