
rule Trojan_BAT_AgentTesla_APK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.APK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {13 35 11 12 11 35 11 20 59 61 13 12 11 20 11 12 19 58 1e 63 59 13 20 } //2
		$a_81_1 = {47 72 61 66 69 6b 5f 53 69 73 74 65 6d 69 2e 52 65 73 6f 75 72 63 65 31 2e 72 65 73 6f 75 72 63 65 73 } //2 Grafik_Sistemi.Resource1.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}