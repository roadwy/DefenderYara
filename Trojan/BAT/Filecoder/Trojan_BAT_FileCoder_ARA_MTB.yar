
rule Trojan_BAT_FileCoder_ARA_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {2e 46 75 63 6b 4f 66 66 } //.FuckOff  2
		$a_80_1 = {5c 55 72 46 69 6c 65 2e 54 58 54 } //\UrFile.TXT  2
		$a_80_2 = {59 6f 75 20 68 61 76 65 20 42 65 65 6e 20 48 61 63 6b 33 64 } //You have Been Hack3d  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}
rule Trojan_BAT_FileCoder_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 55 73 65 72 73 5c 57 6f 72 6d 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 42 53 4f 44 5c 42 53 4f 44 5c 6f 62 6a 5c 44 65 62 75 67 5c 42 53 4f 44 2e 70 64 62 } //2 :\Users\Worm\source\repos\BSOD\BSOD\obj\Debug\BSOD.pdb
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_FileCoder_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 9a 0c 00 08 28 ?? ?? ?? 06 00 08 28 ?? ?? ?? 06 00 00 07 17 58 0b 07 06 8e 69 32 e2 } //2
		$a_80_1 = {5c 4c 6f 63 6b 42 49 54 5c 73 79 73 74 65 6d 49 44 } //\LockBIT\systemID  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}
rule Trojan_BAT_FileCoder_ARA_MTB_4{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 07 11 07 06 08 9a 28 ?? ?? ?? 0a 7d ?? ?? ?? 04 06 08 9a 28 ?? ?? ?? 0a 0d 7e ?? ?? ?? 04 11 07 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 28 ?? ?? ?? 2b 39 ?? ?? ?? ?? 09 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 39 ?? ?? ?? ?? 06 08 9a 73 ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 20 50 c3 10 00 6a 2f 4b 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 19 5b 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 05 06 08 9a 11 05 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 06 08 9a 06 08 9a 72 ?? ?? ?? 70 1a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 2b 49 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 19 5b 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 06 06 08 9a 11 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 06 08 9a 06 08 9a 72 ?? ?? ?? 70 1a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 07 2c 17 16 0b 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}