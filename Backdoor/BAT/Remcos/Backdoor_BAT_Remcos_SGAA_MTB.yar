
rule Backdoor_BAT_Remcos_SGAA_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SGAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 0d 09 1b 59 20 00 01 00 00 58 20 ff 00 00 00 5f 0d 09 19 28 ?? 00 00 06 0d 09 7e ?? 00 00 04 08 58 61 20 ff 00 00 00 5f 0d 09 7e ?? 00 00 04 59 08 59 13 04 11 04 20 00 01 00 00 58 20 ff 00 00 00 5f 13 04 07 08 11 04 d2 9c 00 08 17 58 0c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}