
rule Trojan_Win32_QakBot_ER_MTB{
	meta:
		description = "Trojan:Win32/QakBot.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 2c 66 8b 04 38 66 33 07 8d 7f 04 66 01 01 8b 44 24 48 } //3
		$a_01_1 = {8a 4c 24 11 0f b6 c9 66 2b c8 8b 44 24 5c 66 89 0c 50 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}