
rule Trojan_Win32_Trickbot_MX_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 03 83 c4 0c 8a 54 14 90 01 01 32 c2 88 03 43 4d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 42 1a 00 00 f7 f9 0f b6 94 15 90 01 04 30 53 ff 83 7d 0c 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 45 90 01 01 8a 8c 15 90 01 04 30 08 40 ff 4d 0c 89 45 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_4{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 85 90 01 04 40 83 c4 04 89 85 90 01 04 0f b6 94 15 90 01 04 30 50 ff 83 bd 90 01 04 00 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 44 24 90 01 01 8a 18 83 c4 0c 8a 54 14 90 01 01 32 da 88 18 40 89 44 24 90 01 01 ff 4c 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_6{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 55 02 00 00 f7 f9 8b 44 24 90 01 01 40 83 c4 38 89 44 24 90 01 01 0f b6 54 14 90 01 01 30 50 ff 83 bc 24 84 02 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8a 03 83 c4 0c 8a 54 14 90 01 01 32 c2 88 03 43 4d 90 00 } //1
		$a_80_1 = {4d 43 64 4d 31 41 77 7c 32 53 61 47 32 72 64 47 7a 79 49 33 55 37 24 4b 25 76 65 74 75 69 56 } //MCdM1Aw|2SaG2rdGzyI3U7$K%vetuiV  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_MX_MTB_8{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {52 53 6a 01 53 50 ff 15 90 01 04 85 c0 5b 0f 95 c0 90 00 } //1
		$a_02_1 = {33 c0 3b f3 7e 90 01 01 8b 4c 24 90 01 01 8d 4c 31 90 01 02 8a 11 88 90 01 05 83 c0 01 83 e9 01 3b c6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_MX_MTB_9{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 85 90 01 04 8d 7f 01 8a 8c 15 90 01 04 30 4f ff 4e 90 00 } //1
		$a_80_1 = {79 4b 61 74 42 62 67 44 77 55 36 78 79 6c 68 51 6d 56 68 46 50 65 73 79 36 64 4c 4f 7a 4c 76 64 56 } //yKatBbgDwU6xylhQmVhFPesy6dLOzLvdV  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_10{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 4f ff 4e 0f 85 90 00 } //1
		$a_80_1 = {67 41 42 75 70 61 65 56 39 7a 61 77 61 68 6f 52 45 4f 35 32 32 32 56 66 33 31 41 36 4e 37 69 50 41 45 } //gABupaeV9zawahoREO5222Vf31A6N7iPAE  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_MX_MTB_11{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 0f 83 c3 01 0f 80 90 01 04 8b 51 0c 88 04 2a 8b 44 24 10 3b d8 90 00 } //1
		$a_02_1 = {6a 40 8b b4 24 4c 01 00 00 56 50 e8 90 01 04 8b 4c 24 90 01 01 81 e1 ff ff 00 00 81 f9 4d 5a 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_MX_MTB_12{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_80_0 = {78 68 6d 7a 74 46 42 54 50 71 76 69 37 54 79 63 61 5a 6c 48 62 32 32 53 70 6f 47 69 4c 4e 30 36 5a 35 58 6f 6f 57 66 } //xhmztFBTPqvi7TycaZlHb22SpoGiLN06Z5XooWf  1
		$a_02_1 = {f7 f9 0f b6 94 15 90 01 04 30 53 ff 83 7d 90 01 01 00 75 90 00 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_13{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 2c 8a 8c 15 90 01 04 30 08 40 83 7d 10 00 89 85 90 01 04 0f 85 90 00 } //1
		$a_80_1 = {34 54 76 46 50 41 44 36 54 78 4d 79 58 36 7a 67 58 61 6b 62 4d 51 74 51 75 6c 59 53 54 47 6d 68 71 79 34 71 } //4TvFPAD6TxMyX6zgXakbMQtQulYSTGmhqy4q  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_MX_MTB_14{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 4e ff 8b 8d 90 01 04 4f 75 90 00 } //1
		$a_80_1 = {7a 73 77 4b 4e 46 34 67 6e 64 31 30 4f 74 4a 6b 66 53 75 35 72 63 6a 6c 4a 46 76 72 72 6c 54 63 57 78 71 77 55 43 79 } //zswKNF4gnd10OtJkfSu5rcjlJFvrrlTcWxqwUCy  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_15{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b9 9a 1e 00 00 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 08 40 89 85 90 01 04 8b 85 90 01 04 4f 90 00 } //1
		$a_80_1 = {33 55 56 6f 5a 50 31 4d 68 76 4a 70 58 74 57 68 58 76 62 4f 42 35 48 72 57 32 4d 75 4e 30 69 57 48 } //3UVoZP1MhvJpXtWhXvbOB5HrW2MuN0iWH  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Trickbot_MX_MTB_16{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 44 24 90 01 01 83 c0 01 89 44 24 90 01 01 8a 54 14 90 01 01 30 50 ff 83 bc 24 90 01 02 00 00 00 0f 85 90 00 } //1
		$a_80_1 = {4c 6c 4c 52 4e 4d 3f 50 50 76 45 7a 64 7b 64 72 57 6c 77 53 3f 39 67 7e 58 62 50 63 62 42 31 7e 6f 4b 39 } //LlLRNM?PPvEzd{drWlwS?9g~XbPcbB1~oK9  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_MX_MTB_17{
	meta:
		description = "Trojan:Win32/Trickbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 14 5b 53 51 48 8b c6 48 ff c6 48 8b 0f 48 8b 00 48 33 c8 58 88 0f 48 ff c7 48 ff cb 48 8b c8 75 } //1
		$a_80_1 = {53 6c 65 65 70 } //Sleep  1
		$a_80_2 = {74 65 6d 70 6c 2e 64 6c 6c } //templ.dll  1
		$a_80_3 = {46 72 65 65 42 75 66 66 65 72 } //FreeBuffer  1
		$a_80_4 = {52 65 6c 65 61 73 65 } //Release  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}