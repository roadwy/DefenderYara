
rule Backdoor_BAT_Androm_AAUK_MTB{
	meta:
		description = "Backdoor:BAT/Androm.AAUK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 fd 00 91 87 2b d0 02 02 7b ?? 00 00 04 06 6f ?? 00 00 06 7d ?? 00 00 04 20 fc 00 91 87 2b b7 02 7b ?? 00 00 04 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0a 20 fe 00 91 87 2b 9a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}