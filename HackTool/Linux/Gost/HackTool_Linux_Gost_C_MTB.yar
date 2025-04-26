
rule HackTool_Linux_Gost_C_MTB{
	meta:
		description = "HackTool:Linux/Gost.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 68 6f 6d 65 2f 67 69 6e 75 65 72 7a 68 2f 63 6f 64 65 2f 73 72 63 2f 67 69 6e 75 65 72 7a 68 2f 67 6f 73 74 2f 62 79 70 61 73 73 2e 67 6f } //1 /home/ginuerzh/code/src/ginuerzh/gost/bypass.go
		$a_01_1 = {67 6f 73 74 2e 75 64 70 54 75 6e 6e 65 6c 43 6f 6e 6e 2e 53 65 74 57 72 69 74 65 44 65 61 64 6c 69 6e 65 } //1 gost.udpTunnelConn.SetWriteDeadline
		$a_01_2 = {67 6f 73 74 2e 71 75 69 63 43 69 70 68 65 72 43 6f 6e 6e 2e 57 72 69 74 65 54 6f 55 44 50 } //1 gost.quicCipherConn.WriteToUDP
		$a_01_3 = {6d 61 69 6e 2e 70 61 72 73 65 42 79 70 61 73 73 } //1 main.parseBypass
		$a_01_4 = {6d 61 69 6e 2e 70 61 72 73 65 49 50 52 6f 75 74 65 73 } //1 main.parseIPRoutes
		$a_01_5 = {67 6f 73 74 2f 63 6d 64 2f 67 6f 73 74 2f 6d 61 69 6e 2e 67 6f } //1 gost/cmd/gost/main.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}