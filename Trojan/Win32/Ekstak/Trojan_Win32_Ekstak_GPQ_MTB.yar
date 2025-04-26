
rule Trojan_Win32_Ekstak_GPQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 a3 37 e7 f9 } //4
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 da 0a 00 8b 94 } //4
		$a_01_2 = {ec bd 25 00 fc bd 25 00 14 be 25 00 24 be 25 00 3c be 25 00 58 be 25 00 6a be 25 00 7c be 25 00 94 be 25 00 a2 be 25 00 b0 be 25 00 c0 be 25 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*4) >=4
 
}