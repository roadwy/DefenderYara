
rule Ransom_Win32_LockerGoga_STR_MTB{
	meta:
		description = "Ransom:Win32/LockerGoga.STR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {4d 69 72 63 5c 73 63 72 69 70 74 2e 69 6e 69 2e 6c 6f 63 6b 65 64 } //1 Mirc\script.ini.locked
		$a_81_1 = {6a 6f 61 6e 6e 61 2e 73 6d 69 74 68 40 64 6f 6d 61 69 6e 2e 63 6f 6d } //1 joanna.smith@domain.com
		$a_81_2 = {63 68 6f 69 63 65 20 2f 74 20 31 20 2f 64 20 79 20 2f 6e 20 3e 6e 75 6c } //1 choice /t 1 /d y /n >nul
		$a_81_3 = {64 65 6c 20 25 30 } //1 del %0
		$a_81_4 = {2e 6c 6f 63 6b 65 64 } //1 .locked
		$a_81_5 = {78 78 78 78 2e 6f 6e 69 6f 6e 2f } //1 xxxx.onion/
		$a_81_6 = {52 45 43 4f 56 45 52 59 5f 52 45 41 44 4d 45 } //1 RECOVERY_README
		$a_81_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_81_8 = {44 65 63 6f 64 69 6e 67 4c 6f 6f 6b 75 70 41 72 72 61 79 } //1 DecodingLookupArray
		$a_81_9 = {43 72 79 70 74 6f 2b 2b 20 52 4e 47 } //1 Crypto++ RNG
		$a_81_10 = {2e 74 6f 72 72 65 6e 74 } //1 .torrent
		$a_81_11 = {2e 6c 6f 63 6b 79 } //1 .locky
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}