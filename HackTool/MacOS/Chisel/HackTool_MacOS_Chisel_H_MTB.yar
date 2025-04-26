
rule HackTool_MacOS_Chisel_H_MTB{
	meta:
		description = "HackTool:MacOS/Chisel.H!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 2a 54 75 6e 6e 65 6c 29 2e 61 63 74 69 76 61 74 69 6e 67 43 6f 6e 6e 57 61 69 74 } //1 (*Tunnel).activatingConnWait
		$a_01_1 = {74 75 6e 6e 65 6c 5f 69 6e 5f 70 72 6f 78 79 2e 67 6f } //1 tunnel_in_proxy.go
		$a_01_2 = {28 2a 77 61 69 74 47 72 6f 75 70 29 2e 44 6f 6e 65 41 6c 6c } //1 (*waitGroup).DoneAll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}