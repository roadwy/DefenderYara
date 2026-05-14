
rule Trojan_Win64_Lazy_ABL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 0f b6 42 01 4d 8d 52 01 0f b6 c0 48 05 00 01 00 00 48 c1 e0 08 48 03 c3 41 0f b6 0c 00 41 0f b6 c0 41 88 4a ff 49 83 eb 01 } //5
		$a_01_1 = {34 98 88 45 ec 0f b6 41 1d 34 e9 88 45 ed 0f b6 41 1e 34 6f 88 45 ee 0f b6 41 1f 34 b4 88 45 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_Win64_Lazy_ABL_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 } //powershell.exe -WindowStyle Hidden -Command   1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 53 61 6e 64 62 6f 78 69 65 } //SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie  1
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 45 78 63 6c 75 73 69 6f 6e 73 5c 50 72 6f 63 65 73 73 65 73 } //SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes  1
		$a_80_3 = {49 6e 73 74 61 6c 6c 69 6e 67 20 70 65 72 73 69 73 74 65 6e 63 65 } //Installing persistence  1
		$a_80_4 = {5c 70 61 79 6c 6f 61 64 2e 65 78 65 } //\payload.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}