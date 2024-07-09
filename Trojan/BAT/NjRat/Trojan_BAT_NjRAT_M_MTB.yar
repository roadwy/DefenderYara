
rule Trojan_BAT_NjRAT_M_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 16 03 04 16 0f ?? 28 ?? 00 00 06 20 b8 0b 00 00 7e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}