
rule Trojan_Win32_Powessere_A{
	meta:
		description = "Trojan:Win32/Powessere.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 6b 58 6a 65 66 89 45 ?? 58 6a 72 66 89 45 ?? 58 6a 6e 66 89 45 } //1
		$a_03_1 = {56 69 72 74 c7 45 ?? 75 61 6c 41 c7 45 ?? 6c 6c 6f 63 c6 45 } //1
		$a_01_2 = {8a 04 07 32 45 ff b1 08 2a cb 8a d0 d2 ea 8b cb d2 e0 0a d0 88 54 3e 01 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}
rule Trojan_Win32_Powessere_A_2{
	meta:
		description = "Trojan:Win32/Powessere.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_03_0 = {6a 6b 58 6a 65 66 89 45 ?? 58 6a 72 66 89 45 ?? 58 6a 6e 66 89 45 ?? 58 6a 65 66 89 45 ?? 58 6a 6c } //1
		$a_01_1 = {32 45 ff b1 08 2a cb 8a d0 d2 ea 8b cb d2 e0 0a d0 88 54 3e 01 ff 45 f8 fe 45 ff 8b 45 f8 fe 45 fe 3b 45 0c 72 } //1
		$a_00_2 = {3d 63 6d 64 5f 25 75 26 76 65 72 73 69 6f 6e 3d } //1 =cmd_%u&version=
		$a_00_3 = {3d 64 65 62 75 67 5f 75 6d 33 5f 25 73 26 76 65 72 73 69 6f 6e 3d } //1 =debug_um3_%s&version=
		$a_00_4 = {72 65 69 6e 73 74 6f 6b } //1 reinstok
		$a_00_5 = {25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 5b 5e 3b 5d 3b 25 73 } //1 %[^;];%[^;];%[^;];%[^;];%s
		$a_00_6 = {65 67 70 6e 61 6d 65 5f 25 78 5f 25 78 } //1 egpname_%x_%x
		$a_00_7 = {3a 2f 2f 25 73 2f 71 00 73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 63 6c 73 69 64 5c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}
rule Trojan_Win32_Powessere_A_3{
	meta:
		description = "Trojan:Win32/Powessere.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 22 00 5c 00 2e 00 2e 00 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 22 00 3b 00 65 00 76 00 61 00 6c 00 } //1 javascript:"\..\mshtml,RunHTMLApplication ";eval
		$a_01_1 = {61 69 64 3d 25 73 26 62 75 69 6c 64 64 61 74 65 3d 25 73 26 69 64 3d 25 73 26 6f 73 3d 25 73 5f } //1 aid=%s&builddate=%s&id=%s&os=%s_
		$a_01_2 = {69 65 78 20 28 5b 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 41 53 43 49 49 2e 47 65 74 53 74 72 69 6e 67 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 27 7b 6c 6f 61 64 65 72 7d 27 29 29 29 22 } //1 iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String('{loader}')))"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}