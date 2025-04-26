
rule Trojan_Win32_Mediyes_A{
	meta:
		description = "Trojan:Win32/Mediyes.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b c7 99 6a 18 83 e2 07 59 03 c2 2b cf c1 f8 03 d3 e3 85 c0 } //1
		$a_03_1 = {ff 76 24 50 53 ff 15 ?? ?? ?? ?? 85 c0 75 04 32 c0 eb 19 33 c0 50 50 ff 75 ?? ff 76 28 } //1
		$a_03_2 = {68 e9 00 00 00 8b 45 0c 50 e8 ?? ?? ff ff 83 c4 08 8b 4d 08 2b 4d 0c 83 e9 05 51 8b 55 0c 83 c2 01 52 e8 } //1
		$a_03_3 = {8b 45 f4 83 3c c5 ?? ?? ?? ?? 00 74 34 8b 4d f4 83 3c cd ?? ?? ?? ?? 00 74 27 8b 55 08 52 8b 45 f4 8b 0c c5 ?? ?? ?? ?? 51 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}