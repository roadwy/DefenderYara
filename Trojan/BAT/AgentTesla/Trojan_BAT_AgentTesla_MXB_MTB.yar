
rule Trojan_BAT_AgentTesla_MXB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_02_0 = {08 1b 5b 18 58 93 28 ?? ?? ?? ?? 60 0d 20 ff 00 00 00 09 1f 0f 08 1b 5d 59 1e 59 1f 1f 5f 63 5f 0d 06 09 d2 6f ?? ?? ?? ?? ?? ?? 08 1e 58 0c 08 02 6f ?? ?? ?? ?? 1b 5a fe 04 } //10
		$a_80_1 = {42 69 74 6d 61 70 } //Bitmap  2
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=14
 
}