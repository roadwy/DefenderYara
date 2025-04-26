
rule Trojan_BAT_Zbot_KAA_MTB{
	meta:
		description = "Trojan:BAT/Zbot.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 0a 06 20 ?? ?? 00 00 58 0a 04 1f 19 64 04 1d 62 60 10 02 06 20 ?? ?? 00 00 58 0a 06 20 ?? ?? 00 00 58 0a 04 03 59 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}