
rule Trojan_Win32_Adylkuzz_D{
	meta:
		description = "Trojan:Win32/Adylkuzz.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 6f 6e 69 67 68 74 20 2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 6c 6d 69 6e 65 2e 73 75 70 65 72 31 30 32 34 2e 63 6f 6d } //1 cryptonight -o stratum+tcp://lmine.super1024.com
		$a_01_1 = {73 75 70 65 72 31 30 32 34 2e 63 6f 6d 2f 73 2f 78 6d 72 2f 6d 69 6e 65 72 64 } //1 super1024.com/s/xmr/minerd
		$a_01_2 = {6d 69 6e 65 63 6f 69 6e 73 31 38 2e 63 6f 6d } //1 minecoins18.com
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4c 4d 53 2e 64 61 74 } //1 taskkill /f /im LMS.dat
		$a_01_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 43 68 72 6f 6d 65 2e 74 78 74 } //1 taskkill /f /im Chrome.txt
		$a_03_5 = {77 69 6e 64 72 69 76 65 72 2e 65 78 65 [0-04] 53 65 72 76 65 72 } //1
		$a_03_6 = {57 48 44 4d 49 44 45 [0-04] 64 69 73 70 6c 61 79 [0-04] 57 69 6e 64 6f 77 73 20 48 61 72 64 77 61 72 65 20 44 72 69 76 65 72 20 4d 61 6e 61 67 65 6d 65 6e 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=3
 
}