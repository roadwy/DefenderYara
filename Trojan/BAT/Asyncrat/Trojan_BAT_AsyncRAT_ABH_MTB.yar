
rule Trojan_BAT_AsyncRAT_ABH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 17 a2 0b 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 79 00 00 00 26 00 00 00 2f 00 00 00 48 03 00 00 54 00 00 00 } //5
		$a_01_1 = {4e 6f 74 70 61 64 5f 53 50 5f } //1 Notpad_SP_
		$a_01_2 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //1 get_WebServices
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_4 = {52 65 6d 6f 74 69 6e 67 50 72 6f 78 79 } //1 RemotingProxy
		$a_01_5 = {42 75 66 66 65 72 65 64 53 74 72 65 61 6d } //1 BufferedStream
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}