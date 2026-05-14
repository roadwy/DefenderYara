
rule Trojan_Win64_XWorm_SXA_MTB{
	meta:
		description = "Trojan:Win64/XWorm.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 63 68 6f 73 74 } //2 svcchost
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //2 powershell.exe -NoProfile -WindowStyle Hidden -Command "Invoke-WebRequest -Uri
		$a_01_2 = {66 69 6e 64 73 74 72 20 2f 52 20 22 5b 30 2d 39 5d 5c 2e 5b 30 2d 39 5d 5c 2e 5b 30 2d 39 5d } //1 findstr /R "[0-9]\.[0-9]\.[0-9]
		$a_01_3 = {44 69 73 61 62 6c 69 6e 67 20 47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65 20 50 72 6f 74 65 63 74 69 6f 6e } //1 Disabling Google Chrome Protection
		$a_01_4 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 69 73 20 64 69 73 61 62 6c 65 64 } //1 Windows Defender is disabled
		$a_01_5 = {44 65 6c 65 74 69 6e 67 20 43 3a 5c 53 79 6d 62 6f 6c 73 } //1 Deleting C:\Symbols
		$a_01_6 = {2d 20 53 6d 61 72 74 53 63 72 65 65 6e 20 69 73 20 64 69 73 61 62 6c 65 64 } //1 - SmartScreen is disabled
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=9
 
}