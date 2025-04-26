
rule HackTool_Win32_Impacket_A{
	meta:
		description = "HackTool:Win32/Impacket.A,SIGNATURE_TYPE_CMDHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 68 00 61 00 73 00 68 00 65 00 73 00 20 00 } //10 -hashes 
		$a_00_1 = {2d 00 6a 00 75 00 73 00 74 00 2d 00 64 00 63 00 2d 00 6e 00 74 00 6c 00 6d 00 } //10 -just-dc-ntlm
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}