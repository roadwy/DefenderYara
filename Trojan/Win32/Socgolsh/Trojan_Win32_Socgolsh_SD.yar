
rule Trojan_Win32_Socgolsh_SD{
	meta:
		description = "Trojan:Win32/Socgolsh.SD,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 90 02 30 22 00 70 00 79 00 70 00 69 00 2d 00 70 00 79 00 22 00 90 00 } //01 00 
		$a_00_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 72 00 75 00 6e 00 20 00 2f 00 74 00 6e 00 20 00 22 00 70 00 79 00 70 00 69 00 2d 00 70 00 79 00 22 00 } //00 00  schtasks /run /tn "pypi-py"
	condition:
		any of ($a_*)
 
}