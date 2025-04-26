
rule Backdoor_Win32_NetWiredRC_A{
	meta:
		description = "Backdoor:Win32/NetWiredRC.A,SIGNATURE_TYPE_PEHSTR_EXT,20 00 1e 00 0e 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 25 73 07 25 73 00 47 45 54 20 25 73 20 48 54 54 50 } //5
		$a_03_1 = {5b 25 2e 32 64 2f 25 2e 32 64 2f 25 64 ?? 25 2e 32 64 3a 25 2e 32 64 3a 25 2e 32 64 5d } //5
		$a_01_2 = {25 6c 6c 75 20 25 63 25 73 07 25 49 36 34 75 07 25 49 36 34 75 20 72 62 } //5 氥畬┠╣ݳ䤥㐶ݵ䤥㐶⁵扲
		$a_01_3 = {25 73 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 %s\Google\Chrome\User Data\Default\Login Data
		$a_01_4 = {25 73 5c 43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 %s\Chromium\User Data\Default\Login Data
		$a_01_5 = {73 65 6c 65 63 74 20 2a 20 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //1 select *  from moz_logins
		$a_01_6 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 6e 74 65 6c 6c 69 46 6f 72 6d 73 5c 53 74 6f 72 61 67 65 32 } //1 \Internet Explorer\IntelliForms\Storage2
		$a_01_7 = {25 73 5c 54 68 75 6e 64 65 72 62 69 72 64 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s\Thunderbird\profiles.ini
		$a_01_8 = {25 73 5c 4f 70 65 72 61 5c 4f 70 65 72 61 5c 70 72 6f 66 69 6c 65 5c 77 61 6e 64 2e 64 61 74 } //1 %s\Opera\Opera\profile\wand.dat
		$a_01_9 = {25 73 5c 2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //1 %s\.purple\accounts.xml
		$a_01_10 = {25 73 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s\Mozilla\Firefox\profiles.ini
		$a_01_11 = {25 73 5c 4d 6f 7a 69 6c 6c 61 5c 53 65 61 4d 6f 6e 6b 65 79 5c 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s\Mozilla\SeaMonkey\profiles.ini
		$a_01_12 = {52 47 49 32 38 44 51 33 30 51 42 38 51 31 46 37 } //10 RGI28DQ30QB8Q1F7
		$a_01_13 = {0f b7 d1 69 d2 69 90 00 00 c1 e1 10 01 ca 89 } //10
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*10+(#a_01_13  & 1)*10) >=30
 
}