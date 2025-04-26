
rule Backdoor_BAT_Androm_AKKA_MTB{
	meta:
		description = "Backdoor:BAT/Androm.AKKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 8d 19 00 00 01 13 04 16 13 05 38 1b 00 00 00 11 04 11 05 06 11 05 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 11 05 17 58 13 05 11 05 06 8e 69 32 de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}