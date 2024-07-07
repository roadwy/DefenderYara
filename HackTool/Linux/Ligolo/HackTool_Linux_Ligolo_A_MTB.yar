
rule HackTool_Linux_Ligolo_A_MTB{
	meta:
		description = "HackTool:Linux/Ligolo.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 74 6f 63 6f 6c 2e 4c 69 67 6f 6c 6f 44 65 63 6f 64 65 72 } //1 protocol.LigoloDecoder
		$a_01_1 = {2f 6e 69 63 6f 63 68 61 33 30 2f 6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 70 72 6f 74 6f 63 6f 6c } //1 /nicocha30/ligolo-ng/pkg/protocol
		$a_01_2 = {6e 69 63 6f 63 68 61 33 30 2f 6c 69 67 6f 6c 6f 2d 6e 67 2f 63 6d 64 2f 61 67 65 6e 74 } //1 nicocha30/ligolo-ng/cmd/agent
		$a_01_3 = {6e 69 63 6f 63 68 61 33 30 2f 6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 72 65 6c 61 79 } //1 nicocha30/ligolo-ng/pkg/relay
		$a_01_4 = {4c 69 73 74 65 6e 41 6e 64 53 65 72 76 65 } //1 ListenAndServe
		$a_01_5 = {6d 61 78 50 61 79 6c 6f 61 64 53 69 7a 65 46 6f 72 57 72 69 74 65 } //1 maxPayloadSizeForWrite
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}