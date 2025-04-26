
rule Trojan_Win32_Bundpil_BQ_MTB{
	meta:
		description = "Trojan:Win32/Bundpil.BQ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 15 80 31 00 10 8a 02 a2 90 31 00 10 c7 05 84 31 00 10 0a 00 00 00 0f b6 0d 90 31 00 10 83 f1 79 89 0d 8c 31 00 10 } //1
		$a_01_1 = {8b 0d 80 31 00 10 03 4d e4 0f b6 11 33 15 8c 31 00 10 2b 15 84 31 00 10 f7 d2 a1 80 31 00 10 03 45 e4 88 10 eb c6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}