
rule Trojan_AndroidOS_Joker_F{
	meta:
		description = "Trojan:AndroidOS/Joker.F,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 45 76 69 6e 61 44 61 74 61 2d 2d 2d 2d 2d 75 72 6c 3a } //1 getEvinaData-----url:
		$a_01_1 = {6d 6f 53 65 6e 64 53 4d 53 3a } //1 moSendSMS:
		$a_01_2 = {6d 63 70 5f 73 74 72 69 6e 67 42 75 69 6c 64 65 72 2d 2d 6e 75 6c 6c } //1 mcp_stringBuilder--null
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}