
rule Trojan_BAT_Taskun_KAE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 06 08 5d 13 05 06 17 58 08 5d 13 0b 07 11 0b 91 11 04 58 13 0c 07 11 05 91 13 0d 11 0d 11 07 06 1f 16 5d 91 61 13 0e 11 0e 11 0c 59 13 0f 07 11 05 11 0f 11 04 5d d2 9c 06 17 58 0a 06 08 11 08 17 58 5a fe 04 13 10 11 10 2d ae } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}