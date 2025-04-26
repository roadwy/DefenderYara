
rule Trojan_BAT_Blocker_KAA_MTB{
	meta:
		description = "Trojan:BAT/Blocker.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 91 0d 08 18 5d 13 04 04 11 04 9a 13 05 03 08 02 11 05 09 28 ?? 00 00 06 9c 08 05 fe 01 13 06 11 06 2c 07 28 ?? 00 00 0a 0a 00 00 08 17 d6 0c 08 07 31 cb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}