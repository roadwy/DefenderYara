
rule Trojan_AndroidOS_smsAgent_B_MTB{
	meta:
		description = "Trojan:AndroidOS/smsAgent.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2b 39 31 39 31 30 38 33 38 39 30 34 36 } //1 +919108389046
		$a_00_1 = {61 6b 74 69 76 61 74 65 64 } //1 aktivated
		$a_00_2 = {64 63 68 65 63 6b } //1 dcheck
		$a_00_3 = {73 73 65 6e 64 61 61 } //1 ssendaa
		$a_00_4 = {73 65 74 4d 6f 62 69 6c 65 44 61 74 61 45 6e 61 62 6c 65 64 } //1 setMobileDataEnabled
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}