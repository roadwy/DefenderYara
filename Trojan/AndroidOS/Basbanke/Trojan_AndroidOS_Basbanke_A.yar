
rule Trojan_AndroidOS_Basbanke_A{
	meta:
		description = "Trojan:AndroidOS/Basbanke.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 61 64 64 73 61 64 73 61 73 64 61 64 73 } //1 saddsadsasdads
		$a_01_1 = {74 72 61 63 6b 67 67 70 70 73 73 } //1 trackggppss
		$a_01_2 = {77 73 68 5f 57 61 6b 65 75 70 50 68 6f 6e 65 } //1 wsh_WakeupPhone
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}