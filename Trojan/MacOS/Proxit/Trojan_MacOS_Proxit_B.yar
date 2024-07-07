
rule Trojan_MacOS_Proxit_B{
	meta:
		description = "Trojan:MacOS/Proxit.B,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 78 69 74 2e 63 6f 6d 2f 63 6f 6d 6d 6f 6e 2f 63 6f 6e 66 69 67 2e 6c 6f 61 64 56 69 70 65 72 } //1 proxit.com/common/config.loadViper
		$a_00_1 = {2f 63 6e 63 2f 67 72 70 63 6d 6f 64 65 6c 73 2e 28 2a 50 65 65 72 29 } //1 /cnc/grpcmodels.(*Peer)
		$a_00_2 = {70 72 6f 78 69 74 2e 63 6f 6d 2f 63 6f 6d 6d 6f 6e 2f 68 6f 73 74 69 6e 66 6f } //1 proxit.com/common/hostinfo
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}