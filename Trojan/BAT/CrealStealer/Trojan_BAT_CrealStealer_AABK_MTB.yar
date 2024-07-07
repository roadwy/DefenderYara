
rule Trojan_BAT_CrealStealer_AABK_MTB{
	meta:
		description = "Trojan:BAT/CrealStealer.AABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 36 33 62 64 31 38 36 2d 39 34 64 31 2d 34 35 35 37 2d 39 32 31 65 2d 33 31 63 34 34 33 64 34 38 66 38 34 } //1 b63bd186-94d1-4557-921e-31c443d48f84
		$a_01_1 = {47 00 61 00 6c 00 61 00 78 00 79 00 53 00 77 00 61 00 70 00 70 00 65 00 72 00 76 00 32 00 2e 00 65 00 78 00 65 00 } //1 GalaxySwapperv2.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}