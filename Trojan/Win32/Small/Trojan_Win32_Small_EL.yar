
rule Trojan_Win32_Small_EL{
	meta:
		description = "Trojan:Win32/Small.EL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 49 4d 20 77 69 6e 75 70 64 2e 65 78 65 } //1 TASKKILL /F /IM winupd.exe
		$a_01_1 = {70 30 72 6e 30 } //1 p0rn0
		$a_01_2 = {4d 59 46 55 43 4b 49 4e 47 4d 55 54 45 58 5f } //1 MYFUCKINGMUTEX_
		$a_01_3 = {5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 77 69 6e 75 70 64 2e 65 78 65 } //1 \Documents and Settings\Administrator\Application Data\winupd.exe
		$a_01_4 = {8a 08 40 84 c9 75 f9 2b c2 8b f0 8b 07 8b 48 04 8b 44 39 18 3b c3 7e 0d 3b c6 7e 09 2b c6 8b d8 89 45 e8 eb 03 89 5d e8 8d 55 e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}