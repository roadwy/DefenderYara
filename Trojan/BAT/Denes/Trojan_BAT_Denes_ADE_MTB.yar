
rule Trojan_BAT_Denes_ADE_MTB{
	meta:
		description = "Trojan:BAT/Denes.ADE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 0d 00 11 08 17 58 13 08 11 08 11 09 8e 11 06 8c ?? 00 00 01 80 ?? 00 00 04 69 fe 04 0b 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}