
rule Trojan_Win32_Vilsel_DAM_MTB{
	meta:
		description = "Trojan:Win32/Vilsel.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {10 2c 0a 35 a3 f7 cc e6 f7 40 ca ed 45 9a ec 8c ad 7b 0a ac cb 3a 4f ad 33 99 66 cf 11 b7 } //4
		$a_01_1 = {53 00 6f 00 72 00 72 00 79 00 20 00 69 00 20 00 64 00 6f 00 6e 00 27 00 74 00 20 00 77 00 61 00 6e 00 74 00 20 00 77 00 6f 00 72 00 6b 00 20 00 66 00 6f 00 72 00 20 00 79 00 6f 00 75 00 } //1 Sorry i don't want work for you
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}