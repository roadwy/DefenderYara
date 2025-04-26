
rule HackTool_Linux_Ligolo_C_MTB{
	meta:
		description = "HackTool:Linux/Ligolo.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 61 67 65 6e 74 2e 4e 65 77 55 44 50 4c 69 73 74 65 6e 65 72 } //1 ligolo-ng/pkg/agent.NewUDPListener
		$a_01_1 = {28 2a 4c 69 67 6f 6c 6f 44 65 63 6f 64 65 72 29 2e 44 65 63 6f 64 65 } //1 (*LigoloDecoder).Decode
		$a_01_2 = {65 78 70 6c 6f 69 74 2f 6c 69 67 6f 6c 6f 2f 6c 69 67 6f 6c 6f 2d 6e 67 2f 63 6d 64 2f 61 67 65 6e 74 2f 6d 61 69 6e 2e 67 6f } //1 exploit/ligolo/ligolo-ng/cmd/agent/main.go
		$a_01_3 = {6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 61 67 65 6e 74 2e 28 2a 4c 69 73 74 65 6e 65 72 29 2e 4c 69 73 74 65 6e 41 6e 64 53 65 72 76 65 } //1 ligolo-ng/pkg/agent.(*Listener).ListenAndServe
		$a_01_4 = {73 6d 61 72 74 70 69 6e 67 2e 43 6f 6d 6d 61 6e 64 50 69 6e 67 65 72 } //1 smartping.CommandPinger
		$a_01_5 = {6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 72 65 6c 61 79 2e 53 74 61 72 74 52 65 6c 61 79 } //1 ligolo-ng/pkg/relay.StartRelay
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}