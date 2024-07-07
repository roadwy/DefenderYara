
rule TrojanDropper_Win32_Cutwail_AL{
	meta:
		description = "TrojanDropper:Win32/Cutwail.AL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {81 78 0c 63 74 00 56 74 05 83 c2 04 eb eb } //1
		$a_01_1 = {81 f9 cc 77 00 00 75 07 } //1
		$a_01_2 = {75 12 53 64 8b 1d 18 00 00 00 8b 5b 30 ff 75 ec 8f 43 08 5b } //1
		$a_03_3 = {8b 4d 08 c1 e1 0a 2b d1 8d 05 90 01 04 d1 e1 03 c1 23 c2 8b f0 ba 90 00 } //1
		$a_01_4 = {01 55 f8 31 03 83 e9 04 7e 14 03 45 f8 } //1
		$a_01_5 = {e8 0b 00 00 00 90 e8 25 00 00 00 5b ff d0 53 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}