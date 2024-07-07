
rule HackTool_Win32_PWDump_I{
	meta:
		description = "HackTool:Win32/PWDump.I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 61 77 20 70 61 73 73 77 6f 72 64 20 65 78 74 72 61 63 74 6f 72 } //1 raw password extractor
		$a_01_1 = {73 79 73 74 65 6d 20 70 61 73 73 77 6f 72 64 73 } //1 system passwords
		$a_01_2 = {70 61 73 73 77 6f 72 64 73 20 66 72 6f 6d 20 66 69 6c 65 73 } //1 passwords from files
		$a_01_3 = {73 61 76 65 64 75 6d 70 2e 64 61 74 } //1 savedump.dat
		$a_01_4 = {72 65 61 64 69 6e 67 20 68 69 76 65 20 72 6f 6f 74 20 6b 65 79 } //1 reading hive root key
		$a_01_5 = {53 41 4d 5c 44 6f 6d 61 69 6e 73 5c 41 63 63 6f 75 6e 74 } //1 SAM\Domains\Account
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}