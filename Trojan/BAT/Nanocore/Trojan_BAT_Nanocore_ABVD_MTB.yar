
rule Trojan_BAT_Nanocore_ABVD_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 6c 67 6f 72 69 74 68 6d 53 69 6d 75 6c 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 AlgorithmSimulator.Properties.Resources.resources
		$a_01_1 = {33 39 66 33 35 64 31 37 2d 32 63 38 36 2d 34 38 61 31 2d 61 32 38 30 2d 66 37 37 66 62 33 65 35 32 34 38 65 } //1 39f35d17-2c86-48a1-a280-f77fb3e5248e
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}