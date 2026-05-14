
rule Trojan_BAT_Remcos_ZSJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 13 05 38 ?? ff ff ff 02 8c ?? 00 00 1b 03 04 6f ?? 00 00 0a 0b 1b 13 05 38 ?? ff ff ff 06 17 58 0a 0e 04 25 5a 0d 0e 04 09 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}