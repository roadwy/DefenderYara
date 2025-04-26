
rule Worm_BAT_Pesdear_A{
	meta:
		description = "Worm:BAT/Pesdear.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5c 57 6f 72 6d 5c 57 6f 72 6d 5c 6f 62 6a 5c (44 65 62 75 67|52 65 6c 65 61 73 65) 5c [0-08] 2e 70 64 62 } //1
		$a_01_1 = {55 53 42 49 6e 66 65 63 74 00 } //1 单䥂普捥t
		$a_01_2 = {50 32 50 73 70 72 65 61 64 00 } //1 ㉐獐牰慥d
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}