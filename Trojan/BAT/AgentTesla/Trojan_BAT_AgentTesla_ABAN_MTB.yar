
rule Trojan_BAT_AgentTesla_ABAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {fe 04 13 05 20 ?? ?? ?? 00 28 ?? ?? ?? 06 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 00 11 01 11 02 11 03 28 ?? ?? ?? 06 28 ?? ?? ?? 06 20 ?? ?? ?? 00 28 ?? ?? ?? 06 3a ?? ?? ?? ff 26 38 ?? ?? ?? ff 38 ?? ?? ?? ff 38 ?? ?? ?? 00 38 ?? ?? ?? 00 38 ?? ?? ?? ff 00 16 13 03 20 ?? ?? ?? 00 38 ?? ?? ?? ff 38 ?? ?? ?? 00 38 ?? ?? ?? ff 00 11 03 17 58 13 03 20 ?? ?? ?? 00 38 ?? ?? ?? ff 11 00 17 58 13 00 20 ?? ?? ?? 00 38 ?? ?? ?? ff 2a } //2
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {46 00 34 00 2e 00 74 00 41 00 } //1 F4.tA
		$a_01_3 = {48 00 61 00 72 00 6d 00 6f 00 6e 00 79 00 45 00 64 00 69 00 74 00 6f 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 HarmonyEditor.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}