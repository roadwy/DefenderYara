
rule Trojan_Win32_Trickbot_DHK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 33 d2 b9 ?? ?? ?? ?? f7 f1 8b ca [0-32] 03 c1 99 b9 90 1b 00 f7 f9 8b 85 ?? ?? ?? ?? 8a 8c 15 ?? ?? ?? ?? 30 4e ff } //1
		$a_81_1 = {75 62 63 76 34 6d 34 36 63 79 41 57 74 4f 50 46 4a 38 64 73 48 44 6d 79 6a 4e 5a 64 75 42 6a } //1 ubcv4m46cyAWtOPFJ8dsHDmyjNZduBj
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}