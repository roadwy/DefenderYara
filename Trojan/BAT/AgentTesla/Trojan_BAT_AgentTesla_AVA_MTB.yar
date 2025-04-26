
rule Trojan_BAT_AgentTesla_AVA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b 35 2b 3a 2b 3f 00 2b 0b 2b 0c ?? ?? ?? ?? ?? 00 00 de 14 08 2b f2 07 2b f1 08 2c 0a 16 2d 06 08 ?? ?? ?? ?? ?? 00 dc 07 ?? ?? ?? ?? ?? 0d 16 2d cb de 30 06 2b c8 ?? ?? ?? ?? ?? 2b c4 ?? ?? ?? ?? ?? 2b bf 0c 2b be } //10
		$a_80_1 = {4e 65 77 74 6f 6e 73 6f 66 74 2e 4a 73 6f 6e 2e 64 6c 6c } //Newtonsoft.Json.dll  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}