
rule Trojan_Win32_Rlsloup_gen_A{
	meta:
		description = "Trojan:Win32/Rlsloup.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {eb 22 81 bd ?? ?? ff ff 5c 3f 3f 5c 8d 85 ?? ?? ff ff 74 06 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 ff d3 } //1
		$a_03_1 = {74 22 be 0e 00 00 c0 56 68 ?? ?? ?? ?? e8 ?? ?? ff ff 59 59 57 6a 12 } //1
		$a_03_2 = {46 83 f8 74 59 75 55 0f be 06 50 e8 ?? ?? 00 00 46 83 f8 70 59 75 45 8a 06 46 3c 3a } //1
		$a_01_3 = {0f 8f 37 01 00 00 03 c7 89 45 e8 33 c0 83 c1 f0 74 2c ba } //1
		$a_01_4 = {30 14 0e 40 25 ff 00 00 00 46 3b 75 e4 72 ea 5b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}