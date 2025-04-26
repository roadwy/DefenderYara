
rule Trojan_BAT_Zilla_KAV_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 5b 17 59 17 58 8d ?? 00 00 01 0c 06 16 8c ?? 00 00 01 08 17 28 ?? 00 00 0a 18 59 8c ?? 00 00 01 17 8c ?? 00 00 01 12 01 12 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}