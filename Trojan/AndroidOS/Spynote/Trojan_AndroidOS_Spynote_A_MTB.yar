
rule Trojan_AndroidOS_Spynote_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Spynote.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 6e 2f 73 2f 61 70 70 2f 61 53 65 72 76 69 63 65 53 6f 63 6b 65 74 3b } //5 Ln/s/app/aServiceSocket;
		$a_00_1 = {63 6f 6d 2e 78 78 78 2e 62 72 6f 61 64 63 61 73 74 2e 78 78 78 } //5 com.xxx.broadcast.xxx
		$a_00_2 = {6b 65 79 5f 6c 6f 67 67 65 72 30 78 30 30 78 30 4c 6f 67 4f 6e 6c 69 6e 65 30 78 30 30 78 30 } //1 key_logger0x00x0LogOnline0x00x0
		$a_00_3 = {54 65 72 6d 69 6e 61 6c 30 78 30 30 78 30 53 75 63 63 65 73 73 30 78 30 30 78 30 } //1 Terminal0x00x0Success0x00x0
		$a_00_4 = {4d 69 63 72 6f 70 68 6f 6e 65 30 78 30 30 78 30 62 75 73 79 30 78 30 30 78 30 45 78 63 65 70 74 69 6f 6e 30 78 30 30 78 30 6e 75 6c 6c } //1 Microphone0x00x0busy0x00x0Exception0x00x0null
		$a_00_5 = {43 61 6c 6c 50 68 6f 6e 65 30 78 30 30 78 30 53 75 63 63 65 73 73 30 78 30 30 78 30 6e 75 6c 6c } //1 CallPhone0x00x0Success0x00x0null
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=13
 
}