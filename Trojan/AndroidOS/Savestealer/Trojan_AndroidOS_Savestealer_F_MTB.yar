
rule Trojan_AndroidOS_Savestealer_F_MTB{
	meta:
		description = "Trojan:AndroidOS/Savestealer.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 72 6f 62 62 6f 62 2f 67 61 6d 69 6e 67 } //1 com/robbob/gaming
		$a_00_1 = {61 6c 6c 6d 61 63 73 } //1 allmacs
		$a_00_2 = {77 65 62 68 6f 6f 6b 75 72 6c } //1 webhookurl
		$a_00_3 = {73 74 61 72 74 57 61 74 63 68 69 6e 67 } //1 startWatching
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}