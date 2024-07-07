
rule Trojan_BAT_Injector_SO_MTB{
	meta:
		description = "Trojan:BAT/Injector.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //1
		$a_81_1 = {44 69 6e 76 6f 6b 65 50 72 6f 63 65 73 73 48 6f 6c 6c 6f 77 32 } //1 DinvokeProcessHollow2
		$a_81_2 = {56 69 72 75 73 49 6e 66 65 63 74 65 64 } //1 VirusInfected
		$a_81_3 = {43 61 6e 4c 6f 61 64 46 72 6f 6d 44 69 73 6b } //1 CanLoadFromDisk
		$a_81_4 = {4c 6f 61 64 4d 6f 64 75 6c 65 46 72 6f 6d 44 69 73 6b } //1 LoadModuleFromDisk
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}