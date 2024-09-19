
rule Trojan_BAT_Small_SK_MTB{
	meta:
		description = "Trojan:BAT/Small.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {46 61 6b 65 46 75 6e 63 74 69 6f 6e 44 72 69 76 65 72 } //1 FakeFunctionDriver
		$a_00_1 = {44 69 73 61 62 6c 65 52 65 61 6c 54 69 6d 65 50 72 6f 74 65 63 74 69 6f 6e } //1 DisableRealTimeProtection
		$a_00_2 = {41 6e 74 69 56 4d 43 68 65 63 6b } //1 AntiVMCheck
		$a_00_3 = {44 69 73 61 62 6c 65 44 65 66 65 6e 64 65 72 53 65 72 76 69 63 65 73 } //1 DisableDefenderServices
		$a_80_4 = {49 4e 46 41 52 43 54 45 44 20 4c 41 55 4e 43 48 45 52 20 32 4b 32 34 } //INFARCTED LAUNCHER 2K24  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1) >=3
 
}