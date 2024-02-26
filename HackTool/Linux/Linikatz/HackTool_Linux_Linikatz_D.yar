
rule HackTool_Linux_Linikatz_D{
	meta:
		description = "HackTool:Linux/Linikatz.D,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 73 00 20 00 2d 00 61 00 65 00 6f 00 20 00 72 00 75 00 73 00 65 00 72 00 2c 00 72 00 67 00 72 00 6f 00 75 00 70 00 2c 00 70 00 69 00 64 00 2c 00 70 00 70 00 69 00 64 00 2c 00 61 00 72 00 67 00 73 00 } //00 00  ps -aeo ruser,rgroup,pid,ppid,args
	condition:
		any of ($a_*)
 
}