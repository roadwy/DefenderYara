
rule HackTool_Linux_Chisel_B_MTB{
	meta:
		description = "HackTool:Linux/Chisel.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 70 69 6c 6c 6f 72 61 2f 63 68 69 73 65 6c 2f 63 6c 69 65 6e 74 } //1 jpillora/chisel/client
		$a_01_1 = {6a 70 69 6c 6c 6f 72 61 2f 63 68 69 73 65 6c 2f 73 68 61 72 65 2f 74 75 6e 6e 65 6c 2e 4e 65 77 50 72 6f 78 79 } //1 jpillora/chisel/share/tunnel.NewProxy
		$a_01_2 = {63 68 69 73 65 6c 2d 6d 61 73 74 65 72 77 6f 73 65 72 76 65 72 2f 6d 61 69 6e 2e 67 6f } //1 chisel-masterwoserver/main.go
		$a_01_3 = {63 68 69 73 65 6c 2f 73 68 61 72 65 2f 74 75 6e 6e 65 6c 2e 6c 69 73 74 65 6e 55 44 50 } //1 chisel/share/tunnel.listenUDP
		$a_01_4 = {67 69 74 68 75 62 2e 63 6f 6d 2f 70 6f 72 74 61 69 6e 65 72 2f 61 67 65 6e 74 2f } //-2 github.com/portainer/agent/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*-2) >=3
 
}