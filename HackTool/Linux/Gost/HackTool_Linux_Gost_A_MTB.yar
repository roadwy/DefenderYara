
rule HackTool_Linux_Gost_A_MTB{
	meta:
		description = "HackTool:Linux/Gost.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 6f 73 74 2e 42 79 70 61 73 73 } //1 gost.Bypass
		$a_01_1 = {67 6f 73 74 2e 73 73 68 43 6f 6e 6e } //1 gost.sshConn
		$a_01_2 = {2f 67 6f 2d 67 6f 73 74 2f 67 6f 73 6f 63 6b 73 } //5 /go-gost/gosocks
		$a_01_3 = {2f 67 6f 2d 67 6f 73 74 2f 74 6c 73 2d 64 69 73 73 65 63 74 6f 72 } //5 /go-gost/tls-dissector
		$a_01_4 = {67 6f 73 74 2e 68 32 54 72 61 6e 73 70 6f 72 74 65 72 } //1 gost.h2Transporter
		$a_01_5 = {67 6f 73 74 2e 46 69 6c 74 65 72 } //1 gost.Filter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}