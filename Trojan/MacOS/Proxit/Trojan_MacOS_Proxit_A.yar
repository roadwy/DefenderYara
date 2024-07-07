
rule Trojan_MacOS_Proxit_A{
	meta:
		description = "Trojan:MacOS/Proxit.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 78 69 74 2e 63 6f 6d 2f 70 65 65 72 } //1 proxit.com/peer
		$a_00_1 = {43 6e 63 41 64 64 72 65 73 73 } //1 CncAddress
		$a_00_2 = {70 72 6f 78 69 74 2e 63 6f 6d 2f 63 6f 6d 6d 6f 6e 2f 63 6f 6e 66 69 67 2e 6c 6f 61 64 56 69 70 65 72 } //1 proxit.com/common/config.loadViper
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}