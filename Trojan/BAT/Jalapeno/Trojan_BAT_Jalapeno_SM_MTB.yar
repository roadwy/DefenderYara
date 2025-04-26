
rule Trojan_BAT_Jalapeno_SM_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 07 18 5a 9e 00 07 17 58 0b 07 20 e8 03 00 00 fe 04 0c 08 2d e8 } //2
		$a_81_1 = {24 35 65 63 32 30 38 62 33 2d 30 31 38 38 2d 34 62 63 31 2d 39 63 63 33 2d 30 62 66 61 36 65 36 66 32 63 33 39 } //1 $5ec208b3-0188-4bc1-9cc3-0bfa6e6f2c39
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}