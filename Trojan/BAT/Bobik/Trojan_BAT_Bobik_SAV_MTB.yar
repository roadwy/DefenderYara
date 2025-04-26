
rule Trojan_BAT_Bobik_SAV_MTB{
	meta:
		description = "Trojan:BAT/Bobik.SAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 16 6a 6f 24 00 00 0a 72 ?? ?? ?? 70 0c 73 25 00 00 0a 13 05 73 26 00 00 0a 13 06 11 06 06 73 27 00 00 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f 28 00 00 0a 73 29 00 00 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}