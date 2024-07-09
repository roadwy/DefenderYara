
rule Trojan_BAT_Asyncrat_VN_MTB{
	meta:
		description = "Trojan:BAT/Asyncrat.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 07 02 07 91 11 ?? 61 09 06 91 61 d2 9c 06 03 6f ?? ?? ?? 0a 17 59 fe ?? 13 ?? 11 ?? 2c ?? 16 0a 2b ?? 06 17 58 0a 07 17 58 0b 07 02 8e 69 17 59 fe ?? 16 fe ?? 13 ?? 11 ?? 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}