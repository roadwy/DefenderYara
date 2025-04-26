
rule Backdoor_BAT_CryptInject_MTB{
	meta:
		description = "Backdoor:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {6f 04 00 00 0a 7e 0e 00 00 04 3a 11 00 00 00 14 fe 06 1c 00 00 06 73 05 00 00 0a 80 0e 00 00 04 7e 0e 00 00 04 28 01 00 00 2b 28 02 00 00 2b 73 08 00 00 0a 2a } //1
		$a_02_1 = {00 00 04 7e 0f 00 00 04 3a 11 00 00 00 14 fe 06 ?? 00 00 06 73 ?? 00 00 0a 80 ?? 00 00 04 7e ?? 00 00 04 28 01 00 00 2b 28 02 00 00 2b 2a } //1
		$a_02_2 = {28 18 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a fe 0e 00 00 fe 0c 00 00 28 19 00 00 06 dd 06 00 00 00 26 dd 00 00 00 00 2a } //1
		$a_02_3 = {fe 0e 00 00 fe 0c 00 00 90 0a 20 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a fe 0e 00 00 fe 0c 00 00 28 ?? 00 00 06 dd 06 00 00 00 26 dd 00 00 00 00 2a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=2
 
}
rule Backdoor_BAT_CryptInject_MTB_2{
	meta:
		description = "Backdoor:BAT/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 00 77 00 65 00 74 00 79 00 2e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //1 swety.Program
		$a_01_1 = {61 00 72 00 75 00 6e 00 63 00 61 00 63 00 68 00 65 00 69 00 61 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 aruncacheia.Properties.Resources
		$a_01_2 = {41 73 79 6e 63 43 61 6c 6c 62 61 63 6b } //1 AsyncCallback
		$a_01_3 = {5f 5f 46 69 78 75 70 44 61 74 61 } //1 __FixupData
		$a_01_4 = {44 58 4f 52 } //1 DXOR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}