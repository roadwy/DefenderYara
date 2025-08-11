
rule Trojan_Win32_Dacic_PGC_MTB{
	meta:
		description = "Trojan:Win32/Dacic.PGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c5 89 45 fc 57 8d 85 f0 ee ff ff 50 68 00 10 00 00 8d 8d f8 ee ff ff 33 ff 51 89 bd f4 ee ff ff } //5
		$a_01_1 = {43 3a 5c 48 57 49 44 2e 74 78 74 00 43 3a 5c 00 0d 2b 32 22 3a 27 2f 3f 03 3d 2b 21 07 71 34 32 3d 39 33 33 70 31 13 35 28 38 2c 31 05 15 4b 59 44 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}