
rule Trojan_BAT_Disstl_DAC_MTB{
	meta:
		description = "Trojan:BAT/Disstl.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,25 00 25 00 09 00 00 "
		
	strings :
		$a_80_0 = {44 69 73 63 6f 72 64 } //Discord  5
		$a_80_1 = {50 72 69 6e 63 69 70 61 6c 57 6f 72 6b 65 72 } //PrincipalWorker  4
		$a_80_2 = {47 65 74 4f 73 46 75 6c 6c 6e 61 6d 65 } //GetOsFullname  4
		$a_80_3 = {47 65 74 48 61 72 64 44 72 69 76 65 53 65 72 69 61 6c 4e 75 6d 62 65 72 } //GetHardDriveSerialNumber  4
		$a_80_4 = {44 65 6c 65 74 65 56 61 6c 75 65 46 72 6f 6d 52 65 67 69 73 74 72 79 } //DeleteValueFromRegistry  4
		$a_80_5 = {63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 } //capGetDriverDescriptionA  4
		$a_80_6 = {43 61 6d 65 72 61 45 78 69 73 74 73 } //CameraExists  4
		$a_80_7 = {53 74 61 72 74 75 70 43 6f 70 69 65 64 41 73 73 65 6d 62 6c 79 46 69 6c 65 53 74 72 65 61 6d } //StartupCopiedAssemblyFileStream  4
		$a_80_8 = {4d 75 74 65 78 4e 61 6d 65 } //MutexName  4
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4+(#a_80_6  & 1)*4+(#a_80_7  & 1)*4+(#a_80_8  & 1)*4) >=37
 
}