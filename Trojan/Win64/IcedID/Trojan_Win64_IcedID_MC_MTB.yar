
rule Trojan_Win64_IcedID_MC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //10 PluginInit
		$a_01_1 = {41 31 6e 63 5a 43 37 4f } //1 A1ncZC7O
		$a_01_2 = {42 71 44 6b 57 78 } //1 BqDkWx
		$a_01_3 = {44 6b 52 58 4e 6d 67 4d 72 47 } //1 DkRXNmgMrG
		$a_01_4 = {4b 72 50 33 73 63 66 } //1 KrP3scf
		$a_01_5 = {50 54 4f 35 2e 64 6c 6c } //1 PTO5.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MC_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 61 68 67 64 61 67 79 75 73 64 61 6a 73 64 6b 61 73 } //10 fahgdagyusdajsdkas
		$a_01_1 = {44 4b 35 64 6a 57 43 } //1 DK5djWC
		$a_01_2 = {44 4f 68 45 4d 50 63 41 76 } //1 DOhEMPcAv
		$a_01_3 = {51 4d 59 61 5a 4e 38 } //1 QMYaZN8
		$a_01_4 = {51 52 49 74 77 4a 66 6d } //1 QRItwJfm
		$a_01_5 = {55 69 73 47 31 74 61 4d } //1 UisG1taM
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MC_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 30 48 89 04 24 eb ?? 48 8b 44 24 38 48 89 44 24 08 eb ?? 48 8b 04 24 48 ff c0 eb ?? 8a 09 88 08 eb ?? 48 89 4c 24 08 48 83 ec 28 eb ?? 48 ff c0 48 89 44 24 08 eb } //10
		$a_01_1 = {42 6e 51 78 74 5a 77 4a 65 6d 79 4f 4d } //2 BnQxtZwJemyOM
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}
rule Trojan_Win64_IcedID_MC_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 08 00 00 "
		
	strings :
		$a_01_0 = {76 6c 75 5a 67 70 79 6f 4a 6b 79 50 5a 6c 7a 59 4c } //5 vluZgpyoJkyPZlzYL
		$a_01_1 = {63 49 46 46 41 63 63 65 73 73 54 61 67 4d 65 74 68 6f 64 73 } //2 cIFFAccessTagMethods
		$a_01_2 = {63 49 46 46 43 49 45 4c 61 62 54 6f 52 47 42 49 6e 69 74 } //2 cIFFCIELabToRGBInit
		$a_01_3 = {63 49 46 46 43 49 45 4c 61 62 54 6f 58 59 5a } //2 cIFFCIELabToXYZ
		$a_01_4 = {63 49 46 46 43 68 65 63 6b 54 69 6c 65 } //2 cIFFCheckTile
		$a_01_5 = {63 49 46 46 43 68 65 63 6b 70 6f 69 6e 74 44 69 72 65 63 74 6f 72 79 } //2 cIFFCheckpointDirectory
		$a_01_6 = {63 49 46 46 43 6c 65 61 6e 75 70 } //2 cIFFCleanup
		$a_01_7 = {63 49 46 46 43 6c 69 65 6e 74 4f 70 65 6e } //2 cIFFClientOpen
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=19
 
}
rule Trojan_Win64_IcedID_MC_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 } //1
		$a_01_1 = {48 8b 40 60 48 8b 40 20 48 8d 54 24 60 e9 3d 02 00 00 } //1
		$a_01_2 = {48 8b 4c 24 48 0f b6 44 01 10 8b 4c 24 78 66 3b db 74 50 } //5
		$a_01_3 = {33 c8 8b c1 48 63 4c 24 44 e9 a4 00 00 00 } //5
		$a_01_4 = {48 8b 54 24 58 88 04 0a e9 dc fd ff ff } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=15
 
}