
rule Trojan_BAT_Stealer_ABXA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ABXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 74 0a 00 00 1b 11 21 1f 64 5d 17 9c 11 08 74 ?? 00 00 1b 11 21 11 08 74 ?? 00 00 1b 8e 69 5d 11 21 20 00 01 00 00 5d d2 9c } //3
		$a_03_1 = {19 8d 05 00 00 01 25 16 12 2b 20 6b 01 00 00 20 43 01 00 00 28 ?? 00 00 06 9c 25 17 12 2b 20 df 03 00 00 20 f6 03 00 00 28 ?? 00 00 06 9c 25 18 12 2b 20 e7 01 00 00 20 cd 01 00 00 28 ?? 00 00 06 9c 13 43 1f 2f 13 53 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}