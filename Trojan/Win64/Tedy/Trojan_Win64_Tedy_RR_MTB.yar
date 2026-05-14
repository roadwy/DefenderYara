
rule Trojan_Win64_Tedy_RR_MTB{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {94 33 01 00 b5 33 01 00 d3 33 01 00 f1 33 01 00 0f 34 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_RR_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 80 30 84 41 80 70 01 85 41 80 70 02 86 41 80 70 03 87 41 80 70 04 88 41 80 70 05 89 41 80 70 06 8a 41 80 70 07 8b 41 80 70 08 8c 41 80 70 09 8d 41 80 70 0a 8e 41 88 78 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_RR_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 03 ce 48 89 8c 24 e0 00 00 00 48 33 94 24 08 01 00 00 48 89 94 24 d8 00 00 00 4c 8b ac 24 00 01 00 00 4d 03 dd 4c 89 9c 24 d0 00 00 00 48 8b bc 24 f8 00 00 00 48 33 f7 44 89 84 24 f4 00 00 00 45 8b f9 45 2b f8 41 83 ff 20 7e 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Tedy_RR_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 69 73 63 6f 72 64 5f 67 61 6d 65 5f 73 64 6b 2e 64 6c 6c } //1 discord_game_sdk.dll
		$a_01_1 = {44 69 73 63 6f 72 64 43 72 65 61 74 65 } //1 DiscordCreate
		$a_01_2 = {61 70 69 2d 6d 73 2d 77 69 6e 2d 63 72 74 2d 6c 6f 63 61 6c 65 2d 6c 31 2d 31 2d 30 2e 64 6c 6c } //1 api-ms-win-crt-locale-l1-1-0.dll
		$a_01_3 = {36 6f 6f 50 62 41 50 54 } //1 6ooPbAPT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_Tedy_RR_MTB_5{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 03 ce 48 89 8c 24 e0 00 00 00 48 33 94 24 08 01 00 00 48 89 94 24 d8 00 00 00 4c 8b ac 24 00 01 00 00 4d 03 dd 4c 89 9c 24 d0 00 00 00 48 8b bc 24 f8 00 00 00 48 33 f7 44 89 84 24 f4 00 00 00 45 8b f9 45 2b f8 41 83 ff 20 7e 06 } //1
		$a_01_1 = {30 49 43 33 62 39 78 51 6c 49 59 44 45 4a 55 33 } //1 0IC3b9xQlIYDEJU3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Tedy_RR_MTB_6{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 33 c2 c1 ea 08 0f b6 c8 0f b6 46 05 41 33 94 [0-06] 48 33 c2 c1 ea 08 0f b6 c8 0f b6 46 06 41 33 94 [0-06] 48 33 c2 c1 ea 08 0f b6 c8 0f b6 46 07 48 83 c6 08 41 33 94 [0-06] 48 33 c2 c1 ea 08 0f b6 c8 41 33 94 [0-06] 8b ca 49 83 e8 01 } //1
		$a_01_1 = {62 64 61 74 61 5f 70 61 63 6b 5c 6a 6f 62 66 73 5f 62 2e 6a 73 } //1 bdata_pack\jobfs_b.js
		$a_01_2 = {62 64 61 74 61 5f 70 61 63 6b 5c 6a 6f 62 66 73 5f 6e 2e 6a 73 } //1 bdata_pack\jobfs_n.js
		$a_01_3 = {62 64 61 74 61 5f 70 61 63 6b 5c 6a 70 61 63 6b 2e 6a 73 } //1 bdata_pack\jpack.js
		$a_01_4 = {62 64 61 74 61 5f 70 61 63 6b 5c 75 67 61 74 65 2e 65 78 65 } //1 bdata_pack\ugate.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_Tedy_RR_MTB_7{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {08 a8 a7 31 bf 13 0f 52 f2 ec 32 6c 81 0f } //1
		$a_00_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 } //1 msiexec.exe
		$a_00_2 = {72 00 70 00 6f 00 65 00 64 00 63 00 61 00 6d 00 75 00 73 00 76 00 } //1 rpoedcamusv
		$a_00_3 = {6d 00 65 00 77 00 75 00 69 00 66 00 73 00 6f 00 61 00 72 00 70 00 63 00 76 00 78 00 67 00 68 00 21 00 } //1 mewuifsoarpcvxgh!
		$a_00_4 = {52 00 55 00 56 00 45 00 48 00 3f 00 49 00 4a 00 44 00 71 00 58 00 46 00 41 00 74 00 50 00 59 00 5a 00 6c 00 67 00 6d 00 6e 00 63 00 } //1 RUVEH?IJDqXFAtPYZlgmnc
		$a_00_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 45 00 6e 00 74 00 72 00 69 00 65 00 73 00 } //1 Software\Microsoft\Windows\CurrentVersion\Installer\RunOnceEntries
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}