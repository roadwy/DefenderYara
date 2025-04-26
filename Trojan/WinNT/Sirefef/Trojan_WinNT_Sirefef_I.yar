
rule Trojan_WinNT_Sirefef_I{
	meta:
		description = "Trojan:WinNT/Sirefef.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 0b ff 15 ?? ?? ?? ?? 8b f8 85 ff 7c 10 ff 75 0c 8d 46 04 ff 75 08 e8 ?? ?? ?? ?? 8b d8 6a 00 } //1
		$a_01_1 = {b9 ff ff 00 00 66 89 4e 38 8b 4f 24 89 4e 24 8b 4f 28 89 4e 28 8b 4f 2c 89 4e 2c 8b 4f 30 89 4e 30 0f b7 4f 2c 8b 57 28 2b d1 0f b7 4f 24 83 c4 0c ff 75 0c 03 d1 89 56 30 ff 75 08 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_WinNT_Sirefef_I_2{
	meta:
		description = "Trojan:WinNT/Sirefef.I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 3f 00 3f 00 5c 00 25 00 30 00 38 00 78 00 5c 00 55 00 5c 00 40 00 25 00 30 00 38 00 78 00 00 00 } //1
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 00 } //1
		$a_00_2 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 24 00 4e 00 74 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 4b 00 42 00 25 00 75 00 24 00 } //1 \systemroot\$NtUninstallKB%u$
		$a_00_3 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 5c 00 25 00 49 00 36 00 34 00 75 00 } //1 \driver\%I64u
		$a_01_4 = {8b 43 3c 8b 6c 18 78 03 eb 8b 4d 18 8b 75 20 8b 55 24 03 d3 03 f3 ad 60 8d 34 03 33 ff 8b c7 b9 3f 00 01 00 0f b6 c0 03 c7 f7 e1 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*3) >=5
 
}
rule Trojan_WinNT_Sirefef_I_3{
	meta:
		description = "Trojan:WinNT/Sirefef.I,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 0b ff 15 ?? ?? ?? ?? 8b f8 85 ff 7c 10 ff 75 0c 8d 46 04 ff 75 08 e8 ?? ?? ?? ?? 8b d8 6a 00 } //1
		$a_01_1 = {b9 ff ff 00 00 66 89 4e 38 8b 4f 24 89 4e 24 8b 4f 28 89 4e 28 8b 4f 2c 89 4e 2c 8b 4f 30 89 4e 30 0f b7 4f 2c 8b 57 28 2b d1 0f b7 4f 24 83 c4 0c ff 75 0c 03 d1 89 56 30 ff 75 08 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_WinNT_Sirefef_I_4{
	meta:
		description = "Trojan:WinNT/Sirefef.I,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 3f 00 3f 00 5c 00 25 00 30 00 38 00 78 00 5c 00 55 00 5c 00 40 00 25 00 30 00 38 00 78 00 00 00 } //1
		$a_00_1 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 00 } //1
		$a_00_2 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 24 00 4e 00 74 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 4b 00 42 00 25 00 75 00 24 00 } //1 \systemroot\$NtUninstallKB%u$
		$a_00_3 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 5c 00 25 00 49 00 36 00 34 00 75 00 } //1 \driver\%I64u
		$a_01_4 = {8b 43 3c 8b 6c 18 78 03 eb 8b 4d 18 8b 75 20 8b 55 24 03 d3 03 f3 ad 60 8d 34 03 33 ff 8b c7 b9 3f 00 01 00 0f b6 c0 03 c7 f7 e1 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*3) >=5
 
}