
rule Worm_WinNT_Inqtana_D_MTB{
	meta:
		description = "Worm:WinNT/Inqtana.D!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 70 70 6c 65 63 30 72 65 2e 74 67 7a } //1 applec0re.tgz
		$a_00_1 = {70 77 6e 65 64 2e 64 79 6c 69 62 } //1 pwned.dylib
		$a_00_2 = {49 6e 71 54 65 73 74 2e 6a 61 76 61 } //1 InqTest.java
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}