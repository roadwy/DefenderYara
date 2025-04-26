
rule Trojan_Win64_Doina_SPDG_MTB{
	meta:
		description = "Trojan:Win64/Doina.SPDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 31 33 2e 31 30 35 2e 32 32 34 2e 38 31 3a 38 30 38 38 2f 67 6f 6f 67 6c 65 2e 68 74 6d } //3 http://113.105.224.81:8088/google.htm
		$a_03_1 = {63 6d 64 20 2f 63 20 74 61 73 6b 6c 69 73 74 ?? 64 61 74 61 2e 74 78 74 } //1
		$a_01_2 = {77 69 72 65 73 68 61 72 6b } //2 wireshark
		$a_01_3 = {47 61 6d 65 54 72 6f 79 48 6f 72 73 65 44 65 74 65 63 74 } //1 GameTroyHorseDetect
		$a_01_4 = {57 69 6e 4e 65 74 43 61 70 } //2 WinNetCap
		$a_01_5 = {53 70 79 4e 65 74 } //2 SpyNet
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=11
 
}