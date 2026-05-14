
rule HackTool_Win64_ArdentSeat_A_dha{
	meta:
		description = "HackTool:Win64/ArdentSeat.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 2e 65 78 65 20 78 2e 78 2e 78 2e 78 3a 70 6f 72 74 } //1 x.exe x.x.x.x:port
		$a_01_1 = {6d 61 69 6e 2e 64 66 61 64 66 61 66 64 61 73 00 } //1 慭湩搮慦晤晡慤s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}