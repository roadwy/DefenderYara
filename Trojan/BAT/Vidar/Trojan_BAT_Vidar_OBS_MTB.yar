
rule Trojan_BAT_Vidar_OBS_MTB{
	meta:
		description = "Trojan:BAT/Vidar.OBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 06 00 20 05 00 00 00 fe 0c 08 00 9c 20 54 00 00 00 38 10 e5 ff ff 11 27 11 03 19 58 e0 91 1f 18 62 11 27 11 03 18 58 e0 91 1f 10 62 60 11 27 11 03 17 58 e0 91 1e 62 60 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}