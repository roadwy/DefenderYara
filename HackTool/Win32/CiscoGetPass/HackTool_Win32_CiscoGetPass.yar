
rule HackTool_Win32_CiscoGetPass{
	meta:
		description = "HackTool:Win32/CiscoGetPass,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 65 74 50 61 73 73 21 20 20 76 } //02 00  GetPass!  v
		$a_01_1 = {23 45 6e 74 65 72 20 74 68 65 20 43 69 73 63 6f 20 45 6e 63 72 79 70 74 65 64 20 50 61 73 73 77 6f 72 64 3a } //01 00  #Enter the Cisco Encrypted Password:
		$a_01_2 = {54 68 65 20 64 65 63 72 79 70 74 65 64 20 70 61 73 73 77 6f 72 64 20 69 73 } //00 00  The decrypted password is
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}