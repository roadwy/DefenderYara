
rule HackTool_Win32_PWDump{
	meta:
		description = "HackTool:Win32/PWDump,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 77 44 75 6d 70 } //5 PwDump
		$a_80_1 = {5c 53 41 4d 5c 44 6f 6d 61 69 6e 73 5c 41 63 63 6f 75 6e 74 } //\SAM\Domains\Account  1
		$a_80_2 = {5c 43 6f 6e 74 72 6f 6c 5c 4c 73 61 5c } //\Control\Lsa\  1
		$a_00_3 = {52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 57 } //1 RegQueryValueExW
		$a_00_4 = {43 72 79 70 74 43 72 65 61 74 65 48 61 73 68 } //1 CryptCreateHash
	condition:
		((#a_00_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=9
 
}