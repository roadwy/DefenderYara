
rule Trojan_MacOS_MythicAgent_X4{
	meta:
		description = "Trojan:MacOS/MythicAgent.X4,SIGNATURE_TYPE_MACHOHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_00_0 = {50 6f 73 74 52 65 73 70 6f 6e 73 65 } //100 PostResponse
		$a_01_1 = {4d 79 74 68 69 63 49 44 } //100 MythicID
		$a_01_2 = {6a 73 6f 6e 3a 22 6b 69 6c 6c 64 61 74 65 } //100 json:"killdate
		$a_00_3 = {6a 73 6f 6e 3a 22 70 61 79 6c 6f 61 64 } //100 json:"payload
		$a_00_4 = {6a 73 6f 6e 3a 22 73 6f 63 6b 73 } //100 json:"socks
	condition:
		((#a_00_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_00_3  & 1)*100+(#a_00_4  & 1)*100) >=500
 
}