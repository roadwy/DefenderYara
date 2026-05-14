
rule Trojan_Win32_Flystudio_AB_MTB{
	meta:
		description = "Trojan:Win32/Flystudio.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 46 2c 85 c0 74 0b 50 ff 15 88 25 4a 00 83 66 2c 00 83 7e 14 00 74 08 83 66 14 00 33 c0 } //2
		$a_03_1 = {83 ec 0c 50 ff 74 24 ?? 33 c0 89 44 24 ?? 89 44 24 ?? 89 44 24 ?? 8d 54 24 ?? 52 ff d3 8b 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 83 c4 18 } //10
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*10) >=12
 
}
rule Trojan_Win32_Flystudio_AB_MTB_2{
	meta:
		description = "Trojan:Win32/Flystudio.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 8b 34 8b 01 ee b8 47 65 74 50 39 06 75 f1 b8 72 6f 63 41 39 46 04 75 e7 8b 5a 24 01 eb 66 8b 0c 4b 8b 5a 1c 01 eb 8b 04 8b 01 e8 5d 5e 5a 59 5b 89 85 70 ff ff ff b1 72 b2 61 b0 65 30 db c6 85 74 ff ff ff 56 c6 85 75 ff ff ff 69 88 8d 76 ff ff ff c6 85 77 ff ff ff 74 c6 85 78 ff ff ff 75 88 95 79 ff ff ff c6 85 7a ff ff ff 6c c6 85 7b ff ff ff 50 88 8d 7c ff ff ff c6 85 7d ff ff ff 6f c6 85 7e ff ff ff 74 88 85 7f ff ff ff c6 45 80 63 c6 45 81 74 88 5d 82 c6 45 b4 4c c6 45 b5 6f 88 55 b6 c6 45 b7 64 c6 45 b8 4c c6 45 b9 69 c6 45 ba 62 } //6
		$a_01_1 = {65 7a 64 63 6c 6f 75 64 2e 64 6c 6c } //2 ezdcloud.dll
		$a_01_2 = {6d 61 69 6c 74 6f 3a } //2 mailto:
		$a_01_3 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //2 \shell\open\command
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=12
 
}