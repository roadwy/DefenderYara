
rule HackTool_Win32_Nsudo_B{
	meta:
		description = "HackTool:Win32/Nsudo.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 00 3a 00 74 00 } //01 00  u:t
		$a_00_1 = {75 00 3d 00 74 00 } //02 00  u=t
		$a_00_2 = {6e 00 73 00 75 00 64 00 6f 00 } //00 00  nsudo
	condition:
		any of ($a_*)
 
}