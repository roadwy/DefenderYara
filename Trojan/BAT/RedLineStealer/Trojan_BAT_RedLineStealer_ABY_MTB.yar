
rule Trojan_BAT_RedLineStealer_ABY_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 2c 27 20 c5 ?? ?? 81 0a 16 0b 2b 14 02 07 6f de ?? ?? 0a 06 61 20 93 ?? ?? 01 5a 0a 07 17 58 0b 07 02 6f 5d ?? ?? 0a 32 e3 06 2a } //5
		$a_01_1 = {53 65 74 54 65 72 6d 42 75 66 66 65 72 } //1 SetTermBuffer
		$a_01_2 = {52 41 4d 44 69 72 65 63 74 6f 72 79 } //1 RAMDirectory
		$a_01_3 = {47 65 74 41 77 61 69 74 65 72 } //1 GetAwaiter
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}