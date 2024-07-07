
rule Trojan_Win32_ClipBanker_MR_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_02_0 = {0f b6 14 30 0f 90 02 04 81 90 02 05 c1 90 02 02 03 90 01 01 8a 90 02 02 88 90 02 02 40 3b c1 7c e1 90 00 } //5
		$a_81_1 = {63 6c 72 6a 69 74 2e 64 6c 6c } //1 clrjit.dll
		$a_81_2 = {43 4c 52 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CLRCreateInstance
		$a_81_3 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 53 74 72 65 61 6d } //1 GetManifestResourceStream
		$a_81_4 = {52 65 73 6f 75 72 63 65 41 73 73 65 6d 62 6c 79 } //1 ResourceAssembly
		$a_81_5 = {66 6f 72 6d 53 75 62 6d 69 74 55 52 4c } //1 formSubmitURL
		$a_81_6 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 encryptedPassword
		$a_81_7 = {68 74 74 70 3a 2f 2f 62 6f 74 2e 77 68 61 74 69 73 6d 79 69 70 61 64 64 72 65 73 73 2e 63 6f 6d 2f } //1 http://bot.whatismyipaddress.com/
		$a_81_8 = {41 6e 74 69 76 69 72 75 48 75 66 6c 65 70 75 66 66 73 50 72 6f 64 75 63 74 } //1 AntiviruHuflepuffsProduct
		$a_81_9 = {53 4f 46 54 57 41 52 45 5c 57 4f 57 36 34 33 32 4e 6f 64 65 5c 43 6c 69 65 6e 74 73 5c 53 74 61 72 74 4d 65 6e 75 49 6e 74 65 72 6e 65 74 } //1 SOFTWARE\WOW6432Node\Clients\StartMenuInternet
		$a_81_10 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 shell\open\command
		$a_81_11 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //1 BCryptDecrypt
	condition:
		((#a_02_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=10
 
}