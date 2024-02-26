
rule VirTool_Win32_ChromeKey_A{
	meta:
		description = "VirTool:Win32/ChromeKey.A,SIGNATURE_TYPE_PEHSTR,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 6e 64 20 65 6e 64 20 6f 66 20 65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //01 00  find end of encrypted_key
		$a_01_1 = {66 69 6e 64 4b 65 79 46 69 6c 65 73 } //02 00  findKeyFiles
		$a_01_2 = {42 61 73 65 36 34 20 6b 65 79 20 66 6f 72 } //01 00  Base64 key for
		$a_01_3 = {43 68 72 6f 6d 65 } //02 00  Chrome
		$a_01_4 = {44 65 63 6f 64 65 64 20 6b 65 79 } //00 00  Decoded key
	condition:
		any of ($a_*)
 
}