
rule Backdoor_Win32_Dapsol{
	meta:
		description = "Backdoor:Win32/Dapsol,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {4d 61 69 6e 00 63 6f 6e 63 00 [0-04] 2d 70 61 72 74 6e 65 72 [0-04] 2d ?? ?? 40 63 6f 6e 63 65 61 6c 61 72 65 61 } //2
		$a_01_1 = {68 74 74 70 3a 2f 2f 6d 65 6d 62 65 72 73 2e 63 6f 6e 63 65 61 6c 61 72 65 61 2e 63 6f 6d 2f } //1 http://members.concealarea.com/
		$a_01_2 = {48 6f 73 74 3a 20 63 6f 6e 63 65 61 6c 61 72 65 61 2e 63 6f 6d } //1 Host: concealarea.com
		$a_01_3 = {50 48 4f 4e 45 4e 55 4d 42 45 52 } //1 PHONENUMBER
		$a_01_4 = {4d 42 45 52 53 4d 45 4d 42 45 52 53 4d 45 4d 42 45 52 53 } //1 MBERSMEMBERSMEMBERS
		$a_00_5 = {52 61 73 47 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //1 RasGetEntryDialParamsA
		$a_01_6 = {44 49 41 4c 5f 45 52 } //1 DIAL_ER
		$a_00_7 = {6d 6f 64 65 6d } //1 modem
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}
rule Backdoor_Win32_Dapsol_2{
	meta:
		description = "Backdoor:Win32/Dapsol,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_03_0 = {4d 61 69 6e 00 63 6f 6e 63 00 [0-04] 2d 70 61 72 74 6e 65 72 [0-04] 2d ?? ?? 40 64 61 70 73 6f 6c } //2
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 68 65 68 75 6e 2e 63 6f 6d 2f } //2 http://www.thehun.com/
		$a_01_2 = {68 74 74 70 3a 2f 2f 6d 61 64 74 68 75 6d 62 73 2e 63 6f 6d 2f 61 72 63 68 69 76 65 2f } //2 http://madthumbs.com/archive/
		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 75 73 74 6c 65 72 2d 65 78 63 6c 75 73 69 76 65 2e 63 6f 6d 2f } //2 http://www.hustler-exclusive.com/
		$a_01_4 = {68 74 74 70 3a 2f 2f 67 61 6c 6c 65 72 69 65 73 2e 70 61 79 73 65 72 76 65 2e 63 6f 6d 2f 31 2f 33 31 39 35 32 2f 31 } //2 http://galleries.payserve.com/1/31952/1
		$a_00_5 = {52 61 73 47 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //2 RasGetEntryDialParamsA
		$a_01_6 = {44 49 41 4c 5f 45 52 } //2 DIAL_ER
		$a_00_7 = {6d 6f 64 65 6d } //2 modem
		$a_01_8 = {50 48 4f 4e 45 4e 55 4d 42 45 52 } //1 PHONENUMBER
		$a_01_9 = {4d 42 45 52 53 4d 45 4d 42 45 52 53 4d 45 4d 42 45 52 53 } //1 MBERSMEMBERSMEMBERS
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_00_5  & 1)*2+(#a_01_6  & 1)*2+(#a_00_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=11
 
}