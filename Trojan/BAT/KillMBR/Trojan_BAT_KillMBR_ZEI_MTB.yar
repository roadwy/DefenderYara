
rule Trojan_BAT_KillMBR_ZEI_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ZEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 72 cd 01 00 70 17 8c ?? 00 00 01 17 6f ?? 00 00 0a 7e ?? 00 00 0a 72 59 01 00 70 6f ?? 00 00 0a 0b 07 72 eb 01 00 70 17 8c ?? 00 00 01 17 6f ?? 00 00 0a 7e ?? 00 00 0a 72 15 02 00 70 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}