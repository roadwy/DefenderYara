
rule HackTool_Linux_SuspCommandExecution_A{
	meta:
		description = "HackTool:Linux/SuspCommandExecution.A,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 75 00 64 00 6f 00 20 00 2d 00 53 00 20 00 2d 00 70 00 } //5 sudo -S -p
		$a_00_1 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3a 00 } //5 password:
		$a_00_2 = {62 00 61 00 73 00 68 00 20 00 2d 00 63 00 20 00 27 00 62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 64 00 20 00 3c 00 3c 00 3c 00 20 00 } //5 bash -c 'base64 -d <<< 
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5) >=15
 
}