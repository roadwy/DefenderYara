
rule HackTool_MacOS_Ligolo_A_MTB{
	meta:
		description = "HackTool:MacOS/Ligolo.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 69 67 6f 6c 6f 44 65 63 6f 64 65 72 } //1 LigoloDecoder
		$a_01_1 = {6e 69 63 6f 63 68 61 33 30 2f 6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 70 72 6f 74 6f 63 6f 6c } //1 nicocha30/ligolo-ng/pkg/protocol
		$a_01_2 = {6e 69 63 6f 63 68 61 33 30 2f 6c 69 67 6f 6c 6f 2d 6e 67 2f 70 6b 67 2f 72 65 6c 61 79 2e 53 74 61 72 74 52 65 6c 61 79 } //1 nicocha30/ligolo-ng/pkg/relay.StartRelay
		$a_03_3 = {6c 69 67 6f 6c 6f 2d 6e 67 2f 63 6d 64 2f [0-06] 2f 6d 61 69 6e 2e 67 6f } //1
		$a_01_4 = {4c 69 73 74 65 6e 41 6e 64 53 65 72 76 65 } //1 ListenAndServe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}