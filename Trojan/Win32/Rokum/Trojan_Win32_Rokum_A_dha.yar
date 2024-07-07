
rule Trojan_Win32_Rokum_A_dha{
	meta:
		description = "Trojan:Win32/Rokum.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3e 6a 12 5f 23 87 54 12 96 a3 dc 56 0c 69 ad 1e } //1
		$a_01_1 = {45 40 dc a3 fe 05 2e ba 01 83 d9 fa 36 da 7f 98 } //1
		$a_01_2 = {cd ab dc a3 fe 29 34 b1 08 93 df a1 fa 7d 36 98 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}