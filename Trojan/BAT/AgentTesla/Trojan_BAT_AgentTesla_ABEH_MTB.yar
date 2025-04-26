
rule Trojan_BAT_AgentTesla_ABEH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 01 02 11 07 18 5a 18 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 38 ?? ?? ?? ff dd ?? ?? ?? ff 11 03 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}