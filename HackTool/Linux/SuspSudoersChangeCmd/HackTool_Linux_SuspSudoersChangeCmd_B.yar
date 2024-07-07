
rule HackTool_Linux_SuspSudoersChangeCmd_B{
	meta:
		description = "HackTool:Linux/SuspSudoersChangeCmd.B,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 75 00 23 00 2d 00 31 00 } //10 -u#-1
		$a_00_1 = {73 00 75 00 64 00 6f 00 } //1 sudo
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1) >=11
 
}