
rule Trojan_BAT_DarkCloud_SZJF_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.SZJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 13 0f 11 1c 11 09 91 13 ?? 11 ?? 11 ?? 11 ?? 11 ?? 61 19 11 1d 58 61 11 35 61 d2 9c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}