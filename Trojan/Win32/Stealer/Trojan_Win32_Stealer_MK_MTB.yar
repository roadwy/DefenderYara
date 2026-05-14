
rule Trojan_Win32_Stealer_MK_MTB{
	meta:
		description = "Trojan:Win32/Stealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 d9 89 c2 d3 e2 88 d9 8b 74 24 10 0f a5 c6 31 c0 f6 c3 20 0f 45 f2 0f 45 d0 } //15
		$a_01_1 = {d3 e6 89 74 24 58 89 d6 81 f6 98 41 3d 55 89 74 24 58 c7 44 24 44 00 00 00 00 c7 44 24 40 9f 50 ca 31 89 44 24 1c 89 54 24 18 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}
rule Trojan_Win32_Stealer_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Stealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 07 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 63 61 6c 73 74 61 74 65 2e 6b 65 79 } //10 localstate.key
		$a_01_1 = {6f 2f 34 31 2f 74 6f 6b 65 6e 73 2e 74 78 74 } //10 o/41/tokens.txt
		$a_01_2 = {2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 22 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 } //10 -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('
		$a_01_3 = {67 2f 73 63 72 65 65 6e 2f 73 63 72 65 65 6e 2e 62 6d 70 } //10 g/screen/screen.bmp
		$a_01_4 = {5c 4c 6f 67 69 6e 20 44 61 74 61 } //5 \Login Data
		$a_01_5 = {5c 57 65 62 20 44 61 74 61 } //5 \Web Data
		$a_01_6 = {5c 43 6f 6f 6b 69 65 73 } //5 \Cookies
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=55
 
}