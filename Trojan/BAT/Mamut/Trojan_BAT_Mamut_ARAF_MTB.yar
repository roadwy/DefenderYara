
rule Trojan_BAT_Mamut_ARAF_MTB{
	meta:
		description = "Trojan:BAT/Mamut.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 61 74 61 62 61 74 65 2e 52 65 73 6f 75 72 63 65 73 } //2 satabate.Resources
		$a_01_1 = {24 33 36 34 35 44 39 33 41 2d 41 46 42 46 2d 34 42 35 36 2d 42 43 38 41 2d 45 31 32 41 35 41 30 42 41 36 42 41 } //2 $3645D93A-AFBF-4B56-BC8A-E12A5A0BA6BA
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}