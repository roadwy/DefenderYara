
rule Trojan_BAT_Heracles_ARA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 35 38 33 38 38 } //2 $cc7fad03-816e-432c-9b92-001f2d358388
		$a_01_1 = {73 65 72 76 65 72 31 2e 65 78 65 } //2 server1.exe
		$a_01_2 = {2e 72 65 73 6f 75 72 63 65 73 } //2 .resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule Trojan_BAT_Heracles_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 5d 7e ?? ?? ?? 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Heracles_ARA_MTB_3{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 07 91 7e ?? ?? ?? ?? 07 1e 5d 1f 1f 5f 63 d2 61 d2 0c 08 19 63 08 1b 62 60 d2 0c 08 7e ?? ?? ?? ?? 20 00 01 00 00 28 ?? ?? ?? 06 5a 20 00 01 00 00 5d d2 0c 06 07 08 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d b7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Heracles_ARA_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 74 ?? ?? ?? 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 ?? ?? ?? 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? ?? ?? 0a 26 11 0f 1f 60 91 20 c6 00 00 00 59 13 0e 38 } //2
		$a_03_1 = {13 04 11 0a 74 ?? ?? ?? 1b 11 0c 93 13 05 11 0a 74 ?? ?? ?? 1b 11 0c 17 58 93 11 05 61 13 06 1e 13 0e 38 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Heracles_ARA_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 09 08 11 04 6f ?? ?? ?? 0a 11 04 1f 0a 5d 59 d1 6f ?? ?? ?? 0a 26 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d d2 } //2
		$a_03_1 = {00 06 02 08 6f ?? ?? ?? 0a 03 08 07 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 00 08 17 58 0c 08 02 6f ?? ?? ?? 0a fe 04 0d 09 2d d4 } //2
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //1 DownloadFileAsync
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_Heracles_ARA_MTB_6{
	meta:
		description = "Trojan:BAT/Heracles.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 00 30 00 4d 00 67 00 63 00 47 00 6c 00 75 00 5a 00 79 00 41 00 78 00 4c 00 6a 00 45 00 75 00 4d 00 53 00 34 00 78 00 49 00 43 00 31 00 75 00 49 00 44 00 49 00 67 00 4c 00 58 00 63 00 67 00 4d 00 6a 00 41 00 77 00 4d 00 43 00 41 00 2b 00 49 00 45 00 35 00 31 00 62 00 43 00 41 00 6d 00 49 00 45 00 52 00 6c 00 62 00 43 00 41 00 3d 00 } //2 L0MgcGluZyAxLjEuMS4xIC1uIDIgLXcgMjAwMCA+IE51bCAmIERlbCA=
		$a_00_1 = {3a 00 5a 00 6f 00 6e 00 65 00 2e 00 49 00 64 00 65 00 6e 00 74 00 69 00 66 00 69 00 65 00 72 00 } //2 :Zone.Identifier
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //2 DownloadString
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
		$a_01_4 = {41 65 73 4d 61 6e 61 67 65 64 } //2 AesManaged
		$a_01_5 = {2e 72 65 73 6f 75 72 63 65 73 } //2 .resources
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}