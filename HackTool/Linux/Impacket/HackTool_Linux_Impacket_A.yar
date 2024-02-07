
rule HackTool_Linux_Impacket_A{
	meta:
		description = "HackTool:Linux/Impacket.A,SIGNATURE_TYPE_CMDHSTR_EXT,38 00 38 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //05 00  python
		$a_00_1 = {61 00 74 00 65 00 78 00 65 00 63 00 } //05 00  atexec
		$a_00_2 = {64 00 63 00 6f 00 6d 00 65 00 78 00 65 00 63 00 } //05 00  dcomexec
		$a_00_3 = {73 00 6d 00 62 00 65 00 78 00 65 00 63 00 } //05 00  smbexec
		$a_00_4 = {77 00 6d 00 69 00 65 00 78 00 65 00 63 00 } //05 00  wmiexec
		$a_00_5 = {70 00 73 00 65 00 78 00 65 00 63 00 } //32 00  psexec
		$a_00_6 = {2d 00 68 00 61 00 73 00 68 00 65 00 73 00 20 00 } //00 00  -hashes 
	condition:
		any of ($a_*)
 
}