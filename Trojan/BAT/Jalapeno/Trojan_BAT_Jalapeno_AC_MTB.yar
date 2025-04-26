
rule Trojan_BAT_Jalapeno_AC_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 28 28 11 00 00 0a 72 01 00 00 70 02 72 15 00 00 70 28 12 00 00 0a 73 13 00 00 0a 0a 73 14 00 00 0a 0b ?? ?? 06 03 2d 07 72 43 00 00 70 2b 05 72 4f 00 00 70 } //2
		$a_01_1 = {61 31 39 30 36 39 62 62 2d 62 64 39 61 2d 34 63 61 38 2d 62 38 65 62 2d 35 38 36 32 64 64 61 34 34 63 30 32 } //1 a19069bb-bd9a-4ca8-b8eb-5862dda44c02
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}