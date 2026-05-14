
rule Trojan_BAT_Rozena_GPAX_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GPAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 57 69 6e 33 32 00 6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 4f 70 65 6e 50 72 6f 63 65 73 73 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00 49 6e 6a 65 63 74 00 64 77 44 65 73 69 72 65 64 41 63 63 65 73 73 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}