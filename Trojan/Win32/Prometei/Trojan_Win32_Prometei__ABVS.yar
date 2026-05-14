
rule Trojan_Win32_Prometei__ABVS{
	meta:
		description = "Trojan:Win32/Prometei..ABVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 85 05 ff ff ff 77 c6 85 06 ff ff ff 63 c6 85 07 ff ff ff 5a c6 85 08 ff ff ff 44 c6 85 09 ff ff ff 78 c6 85 0a ff ff ff 46 c6 85 0b ff ff ff 71 c6 85 0c ff ff ff 41 c6 85 0d ff ff ff 53 c6 85 0e ff ff ff 45 c6 85 0f ff ff ff 4a c6 85 10 ff ff ff 54 c6 85 11 ff ff ff 4f c6 85 12 ff ff ff 43 c6 85 13 ff ff ff 72 } //5
		$a_80_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 69 6e 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 6f 75 74 70 75 74 66 6f 72 6d 61 74 20 6e 6f 6e 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 43 6f 6d 6d 61 6e 64 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 44 65 6c 6c } //powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath "C:\Windows\Dell  1
		$a_80_2 = {5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //[System.Convert]::FromBase64String  1
		$a_03_3 = {2f 43 20 72 65 6e 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 64 65 6c 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 } //1
		$a_80_4 = {34 35 2e 38 37 2e 31 37 34 2e 38 } //45.87.174.8  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_03_3  & 1)*1+(#a_80_4  & 1)*1) >=9
 
}