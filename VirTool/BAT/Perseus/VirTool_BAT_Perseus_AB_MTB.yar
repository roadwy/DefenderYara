
rule VirTool_BAT_Perseus_AB_MTB{
	meta:
		description = "VirTool:BAT/Perseus.AB!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {64 65 34 66 75 63 6b 79 6f 75 } //1 de4fuckyou
		$a_01_1 = {56 4d 50 72 6f 74 65 63 74 } //1 VMProtect
		$a_01_2 = {42 65 64 73 2d 50 72 6f 74 65 63 74 6f 72 } //1 Beds-Protector
		$a_01_3 = {43 72 79 74 70 6f 4f 62 66 75 73 63 61 74 6f 72 } //1 CrytpoObfuscator
		$a_01_4 = {4f 62 66 75 73 63 61 74 65 64 42 79 47 6f 6c 69 61 74 68 } //1 ObfuscatedByGoliath
		$a_01_5 = {4f 69 43 75 6e 74 4a 6f 6c 6c 79 47 6f 6f 64 44 61 79 59 65 48 61 76 69 6e } //1 OiCuntJollyGoodDayYeHavin
		$a_01_6 = {56 00 32 00 6c 00 75 00 5a 00 47 00 39 00 33 00 63 00 30 00 46 00 77 00 63 00 44 00 51 00 6b 00 } //1 V2luZG93c0FwcDQk
		$a_01_7 = {56 00 32 00 6c 00 75 00 5a 00 47 00 39 00 33 00 63 00 7a 00 6b 00 6b 00 } //1 V2luZG93czkk
		$a_01_8 = {4a 75 6d 70 65 64 2d 4f 76 65 72 2d 54 68 65 2d 4c 61 7a 79 2d 44 6f 67 } //1 Jumped-Over-The-Lazy-Dog
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}