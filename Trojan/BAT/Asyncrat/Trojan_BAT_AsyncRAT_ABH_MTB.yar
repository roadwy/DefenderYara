
rule Trojan_BAT_AsyncRAT_ABH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 17 a2 0b 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 79 00 00 00 26 00 00 00 2f 00 00 00 48 03 00 00 54 00 00 00 } //01 00 
		$a_01_1 = {4e 6f 74 70 61 64 5f 53 50 5f } //01 00  Notpad_SP_
		$a_01_2 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //01 00  get_WebServices
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_4 = {52 65 6d 6f 74 69 6e 67 50 72 6f 78 79 } //01 00  RemotingProxy
		$a_01_5 = {42 75 66 66 65 72 65 64 53 74 72 65 61 6d } //00 00  BufferedStream
	condition:
		any of ($a_*)
 
}