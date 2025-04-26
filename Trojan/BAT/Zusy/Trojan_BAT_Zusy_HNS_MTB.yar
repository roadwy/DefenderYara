
rule Trojan_BAT_Zusy_HNS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 45 51 52 42 32 36 58 33 50 44 45 44 46 57 56 42 4e 4e 7a 37 5a 35 4c 71 76 4a 61 59 68 42 71 7a 4d 50 49 51 62 39 33 59 70 6c 67 4e 48 50 4d 34 31 38 39 6c 49 5a 63 56 52 55 } //1 FEQRB26X3PDEDFWVBNNz7Z5LqvJaYhBqzMPIQb93YplgNHPM4189lIZcVRU
	condition:
		((#a_01_0  & 1)*1) >=1
 
}