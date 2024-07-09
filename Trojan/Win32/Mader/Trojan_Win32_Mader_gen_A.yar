
rule Trojan_Win32_Mader_gen_A{
	meta:
		description = "Trojan:Win32/Mader.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 d0 80 3a 3e 75 45 80 7a 01 58 75 3f 80 7a 02 49 75 39 80 7a 03 54 75 33 8b 42 0c 85 c0 74 26 83 c0 ff 78 21 } //1
		$a_01_1 = {81 39 75 73 65 64 75 18 85 c0 74 12 8b 71 0c 3b 70 0c 7c 0c 7f 08 8b 71 08 3b 70 08 76 02 8b c1 83 c1 5c 4a } //1
		$a_03_2 = {74 31 80 38 79 75 12 80 78 01 65 75 0c 80 78 02 73 75 06 89 7c 24 14 eb 1a 53 e8 ?? ?? ff ff 85 c0 59 75 0b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}