
rule Trojan_BAT_AgentTesla_MBYT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {17 58 08 5d 13 } //1
		$a_01_1 = {17 59 5f 13 } //1 夗፟
		$a_01_2 = {37 00 4b 00 41 00 59 00 51 00 37 00 38 00 35 00 34 00 37 00 37 00 34 00 37 00 32 00 54 00 39 00 34 00 34 00 35 00 45 00 37 00 34 00 } //1 7KAYQ785477472T9445E74
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}