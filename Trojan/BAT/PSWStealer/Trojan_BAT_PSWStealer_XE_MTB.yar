
rule Trojan_BAT_PSWStealer_XE_MTB{
	meta:
		description = "Trojan:BAT/PSWStealer.XE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 } //cdn.discordapp.com/attachments  1
		$a_01_1 = {6f 62 6a 5c 44 65 62 75 67 5c 66 75 64 6c 6f 61 64 65 72 2e 70 64 62 } //1 obj\Debug\fudloader.pdb
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_4 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_5 = {67 6c 79 62 7a 6a 65 70 61 70 6b 69 73 66 } //1 glybzjepapkisf
		$a_01_6 = {54 6f 53 74 72 69 6e 67 } //1 ToString
		$a_01_7 = {73 65 74 5f 50 61 73 73 77 6f 72 64 56 61 6c 75 65 } //1 set_PasswordValue
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}