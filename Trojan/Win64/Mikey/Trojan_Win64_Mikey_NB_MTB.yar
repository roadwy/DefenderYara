
rule Trojan_Win64_Mikey_NB_MTB{
	meta:
		description = "Trojan:Win64/Mikey.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {83 7d 00 00 0f 95 c0 88 07 b0 01 48 8b 4d 08 48 33 cd e8 } //10
		$a_81_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 57 69 6e 64 6f 77 73 50 6f 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c } //1 C:\Windows\system32\WindowsPowerShell\v1.0\powershell
		$a_81_2 = {24 42 6c 6f 63 6b 65 64 46 72 6f 6d 52 65 66 6c 65 63 74 69 6f 6e } //1 $BlockedFromReflection
		$a_81_3 = {24 64 69 73 61 62 6c 65 20 72 65 67 65 64 69 74 } //1 $disable regedit
		$a_81_4 = {24 64 69 73 61 62 6c 65 20 75 61 63 } //1 $disable uac
		$a_81_5 = {24 73 74 61 72 74 20 77 69 74 68 20 77 69 6e 64 6f 77 73 } //1 $start with windows
		$a_81_6 = {68 65 6e 74 61 69 } //1 hentai
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}