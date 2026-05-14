
rule Trojan_Win32_FatBeehive_C_dha{
	meta:
		description = "Trojan:Win32/FatBeehive.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c1 f7 f6 0f b6 c1 03 55 [0-01] 6b c0 55 32 02 88 04 0f 41 83 f9 20 } //1
		$a_03_1 = {8a 44 0f ff 02 04 0f 34 [0-01] 88 04 0f 41 83 f9 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}