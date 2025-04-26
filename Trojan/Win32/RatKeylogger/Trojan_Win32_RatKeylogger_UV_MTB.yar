
rule Trojan_Win32_RatKeylogger_UV_MTB{
	meta:
		description = "Trojan:Win32/RatKeylogger.UV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {52 61 74 53 63 72 65 65 6e 4d 6f 64 75 6c 65 } //1 RatScreenModule
		$a_81_1 = {52 61 74 53 6f 75 6e 64 4d 6f 64 75 6c 65 } //1 RatSoundModule
		$a_81_2 = {52 61 74 46 69 6c 65 53 79 73 74 65 6d 4d 6f 64 75 6c 65 } //1 RatFileSystemModule
		$a_81_3 = {52 61 74 42 72 6f 77 73 65 72 4d 6f 64 75 6c 65 } //1 RatBrowserModule
		$a_81_4 = {52 61 74 4b 65 79 62 6f 61 72 64 4d 6f 64 75 6c 65 } //1 RatKeyboardModule
		$a_81_5 = {52 61 74 4d 61 69 6c 4d 6f 64 75 6c 65 } //1 RatMailModule
		$a_81_6 = {52 61 74 53 74 61 72 74 65 72 5c 52 65 6c 65 61 73 65 20 4d 64 5c 52 61 74 } //1 RatStarter\Release Md\Rat
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}