
rule HackTool_Win32_PWDump{
	meta:
		description = "HackTool:Win32/PWDump,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {50 77 44 75 6d 70 } //01 00 
		$a_80_1 = {5c 53 41 4d 5c 44 6f 6d 61 69 6e 73 5c 41 63 63 6f 75 6e 74 } //\SAM\Domains\Account  01 00 
		$a_80_2 = {5c 43 6f 6e 74 72 6f 6c 5c 4c 73 61 5c } //\Control\Lsa\  01 00 
		$a_00_3 = {52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 57 } //01 00 
		$a_00_4 = {43 72 79 70 74 43 72 65 61 74 65 48 61 73 68 } //00 00 
	condition:
		any of ($a_*)
 
}