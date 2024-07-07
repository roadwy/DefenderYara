
rule Trojan_Win64_CobaltStrike_PI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 01 c2 4c 63 c2 48 8b 55 10 4c 01 c2 0f b6 12 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_PI_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ca 0f af c8 41 8b 90 01 01 03 c1 48 63 c8 48 8b 44 24 90 01 01 0f b6 0c 08 48 8b 44 24 90 01 01 42 0f b6 34 90 01 01 33 f1 8b 4c 24 90 01 01 8b 44 24 90 01 01 03 c1 90 00 } //2
		$a_03_1 = {41 2b c3 2b c3 2b c7 8b c8 48 8b 44 24 90 01 01 40 88 34 08 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}
rule Trojan_Win64_CobaltStrike_PI_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 61 6c 61 73 20 65 20 54 69 72 6f 73 } //1 Balas e Tiros
		$a_01_1 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 28 2e 2e 2e 29 } //1 InternetReadFile(...)
		$a_01_2 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 28 2e 2e 2e 29 } //1 HttpSendRequestA(...)
		$a_01_3 = {2f 68 74 45 70 } //1 /htEp
		$a_01_4 = {6f 73 68 69 2e 61 74 } //1 oshi.at
		$a_01_5 = {55 73 65 72 49 6e 69 74 4d 70 72 4c 6f 67 6f 6e 53 63 72 69 70 74 } //1 UserInitMprLogonScript
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}