
rule HackTool_Linux_Ligolo_B_MTB{
	meta:
		description = "HackTool:Linux/Ligolo.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 6e 69 63 6f 63 68 61 33 30 2f 6c 69 67 6f 6c 6f 2d 6e 67 2f 63 6d 64 2f 70 72 6f 78 79 2f 61 70 70 } //1 /nicocha30/ligolo-ng/cmd/proxy/app
		$a_01_1 = {2f 70 72 6f 78 79 2e 28 2a 4c 69 67 6f 6c 6f 54 75 6e 6e 65 6c 29 2e 48 61 6e 64 6c 65 53 65 73 73 69 6f 6e } //1 /proxy.(*LigoloTunnel).HandleSession
		$a_01_2 = {2f 70 72 6f 74 6f 63 6f 6c 2e 28 2a 4c 69 67 6f 6c 6f 44 65 63 6f 64 65 72 29 2e 44 65 63 6f 64 65 } //1 /protocol.(*LigoloDecoder).Decode
		$a_01_3 = {2f 6c 69 67 6f 6c 6f 2d 6e 67 2f 63 6d 64 2f 70 72 6f 78 79 2f 61 70 70 2e 52 75 6e } //1 /ligolo-ng/cmd/proxy/app.Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}