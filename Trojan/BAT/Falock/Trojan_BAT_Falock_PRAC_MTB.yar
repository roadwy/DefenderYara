
rule Trojan_BAT_Falock_PRAC_MTB{
	meta:
		description = "Trojan:BAT/Falock.PRAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 09 1b 58 08 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 09 17 58 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}