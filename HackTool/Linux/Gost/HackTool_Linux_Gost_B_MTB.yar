
rule HackTool_Linux_Gost_B_MTB{
	meta:
		description = "HackTool:Linux/Gost.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 79 70 61 73 73 2e 50 61 72 73 65 42 79 70 61 73 73 } //1 bypass.ParseBypass
		$a_01_1 = {73 73 68 64 2e 52 65 6d 6f 74 65 46 6f 72 77 61 72 64 43 6f 6e 6e } //1 sshd.RemoteForwardConn
		$a_01_2 = {2f 62 79 70 61 73 73 2f 70 72 6f 74 6f 2f 62 79 70 61 73 73 5f 67 72 70 63 2e 70 62 2e 67 6f } //1 /bypass/proto/bypass_grpc.pb.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}