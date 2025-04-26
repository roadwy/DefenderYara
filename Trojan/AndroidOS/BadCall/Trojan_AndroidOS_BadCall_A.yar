
rule Trojan_AndroidOS_BadCall_A{
	meta:
		description = "Trojan:AndroidOS/BadCall.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 4d 44 5f 50 52 4f 58 59 5f 4d 41 4e 41 43 4b } //1 CMD_PROXY_MANACK
		$a_00_1 = {43 4d 44 5f 52 45 41 44 5f 57 45 42 48 49 53 } //1 CMD_READ_WEBHIS
		$a_01_2 = {70 72 6f 78 79 4d 61 6e 41 63 6b } //1 proxyManAck
		$a_01_3 = {6d 5f 73 74 72 4b 65 65 70 4c 69 6e 6b 52 73 70 } //1 m_strKeepLinkRsp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}