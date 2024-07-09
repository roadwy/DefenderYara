
rule Trojan_BAT_AgentTesla_AT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 13 04 2b 31 09 08 17 8d 03 00 00 01 25 16 11 04 8c 88 00 00 01 a2 14 28 } //2
		$a_01_1 = {50 00 6f 00 6b 00 65 00 72 00 31 00 } //1 Poker1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_AT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 16 00 00 06 0a 06 03 7d 0c 00 00 04 00 02 06 fe 06 17 00 00 06 73 15 00 00 0a 28 } //2
		$a_01_1 = {53 00 74 00 75 00 70 00 69 00 64 00 } //1 Stupid
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_AT_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 1e 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 13 05 08 11 05 6f ?? ?? ?? 0a 09 18 58 0d 09 07 } //2
		$a_01_1 = {43 00 43 00 30 00 31 00 } //1 CC01
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_AT_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 18 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 06 13 06 08 17 8d ?? 00 00 01 25 16 11 06 9c 6f } //2
		$a_01_1 = {71 75 61 6e 6c 79 63 75 61 68 61 6e 67 } //1 quanlycuahang
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_AT_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 4b 07 06 8e 69 5d 13 05 07 11 04 6f ?? ?? ?? 0a 5d 13 08 06 11 05 91 13 09 11 04 11 08 6f ?? ?? ?? 0a 13 0a 02 06 07 28 ?? ?? ?? 06 13 0b 02 11 09 11 0a 11 0b 28 ?? ?? ?? 06 13 0c 06 11 05 02 11 0c 28 ?? ?? ?? 06 9c 07 17 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_AT_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {1a 9a 20 e6 06 00 00 95 e0 95 7e 0e 00 00 04 1a 9a 20 ab 0b 00 00 95 61 7e 0e 00 00 04 1a 9a 20 e2 0c 00 00 95 } //2
		$a_01_1 = {1a 9a 20 94 10 00 00 95 e0 95 7e 0e 00 00 04 1a 9a 20 05 10 00 00 95 61 7e 0e 00 00 04 1a 9a 20 f9 07 00 00 95 2e 03 17 2b 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_AT_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 69 6d 65 5f 44 72 6f 70 70 65 72 5f 31 } //1 Lime_Dropper_1
		$a_01_1 = {4d 4e 4a 4b 6f 6c 4b 38 37 2e 70 64 62 } //1 MNJKolK87.pdb
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 50 61 79 6c 6f 61 64 } //1 DownloadPayload
		$a_01_3 = {66 36 66 61 38 38 36 64 2d 35 36 38 39 2d 34 32 34 33 2d 38 38 39 38 2d 36 32 37 61 37 39 62 34 35 36 36 31 } //1 f6fa886d-5689-4243-8898-627a79b45661
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_AT_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 3b 00 00 06 17 2d 1c 26 28 30 00 00 0a 06 6f 31 00 00 0a 28 32 00 00 0a 28 43 00 00 06 18 2d 06 26 de 09 0a 2b e2 0b 2b f8 26 de d2 } //1
		$a_01_1 = {16 1a 2d 0c 26 02 8e 69 17 59 1a 2d 06 26 2b 24 0a 2b f2 0b 2b f8 02 06 91 16 2c 15 26 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_AT_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.AT!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 00 6d 00 61 00 67 00 69 00 6e 00 65 00 72 00 2e 00 6d 00 61 00 6c 00 68 00 65 00 75 00 72 00 65 00 75 00 78 00 } //1 Imaginer.malheureux
		$a_01_1 = {43 00 61 00 6e 00 53 00 65 00 65 00 6b 00 } //1 CanSeek
		$a_01_2 = {52 43 32 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 RC2CryptoServiceProvider
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}