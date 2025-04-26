
rule Trojan_BAT_AgentTesla_MBBA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 00 0b 44 00 6f 00 64 00 67 00 65 } //1
		$a_01_1 = {24 34 34 35 61 39 38 66 31 2d 35 62 66 64 2d 34 65 63 39 2d 61 66 33 64 2d 62 63 31 63 30 34 65 63 35 36 39 32 } //1 $445a98f1-5bfd-4ec9-af3d-bc1c04ec5692
		$a_01_2 = {42 75 69 6c 64 45 76 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 BuildEvent.Properties.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}