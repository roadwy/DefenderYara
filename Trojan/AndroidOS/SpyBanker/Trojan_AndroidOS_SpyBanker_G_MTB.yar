
rule Trojan_AndroidOS_SpyBanker_G_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 6a 61 6b 65 64 65 67 69 76 75 77 75 77 65 2f 79 65 77 6f } //1 com/jakedegivuwuwe/yewo
		$a_00_1 = {63 6f 6d 2f 63 69 73 6f 6a 65 6d 6f 70 61 74 75 64 65 2f 79 61 7a 69 2f 63 61 74 6f 7a 6f 74 75 } //1 com/cisojemopatude/yazi/catozotu
		$a_00_2 = {63 61 6c 6c 63 61 70 61 62 6c 65 70 68 6f 6e 65 61 63 63 6f 75 6e 74 73 } //1 callcapablephoneaccounts
		$a_00_3 = {73 65 6e 64 5f 6c 6f 67 5f 69 6e 6a 65 63 74 73 } //1 send_log_injects
		$a_00_4 = {67 65 74 63 6c 69 70 64 61 74 61 } //1 getclipdata
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}