
rule Trojan_BAT_AgentTesla_LNS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 0f 01 28 ?? ?? ?? 0a 07 6a 58 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 06 61 20 ?? ?? ?? 00 5f 95 06 1e 64 61 0a 07 17 58 0b 07 6a 04 6e } //10
		$a_01_1 = {24 62 61 32 65 36 61 30 39 2d 66 62 35 33 2d 34 65 65 39 2d 39 38 31 65 2d 33 33 35 62 37 61 32 31 62 63 33 39 } //1 $ba2e6a09-fb53-4ee9-981e-335b7a21bc39
		$a_01_2 = {24 36 62 33 31 61 37 63 33 2d 33 62 61 61 2d 34 37 61 63 2d 61 62 65 31 2d 39 30 32 62 32 37 65 30 66 39 61 63 } //1 $6b31a7c3-3baa-47ac-abe1-902b27e0f9ac
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}