
rule Trojan_AndroidOS_SmsThief_AI{
	meta:
		description = "Trojan:AndroidOS/SmsThief.AI,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 73 61 6d 65 69 61 63 77 65 73 69 } //2 nsameiacwesi
		$a_01_1 = {70 68 72 6c 73 63 65 73 74 70 61 66 65 } //2 phrlscestpafe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}