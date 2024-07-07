
rule TrojanDropper_Win32_Colapea_A{
	meta:
		description = "TrojanDropper:Win32/Colapea.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 81 7d fa bc 07 72 08 66 81 7d fa 3b 08 76 07 } //1
		$a_03_1 = {83 f8 06 75 19 a1 90 01 04 e8 90 01 02 ff ff 83 f8 1e 75 0a b8 02 00 00 00 e8 90 00 } //1
		$a_01_2 = {30 78 32 33 34 32 32 34 34 68 20 69 6e 20 55 73 65 72 33 32 2e 64 6c 6c } //1 0x2342244h in User32.dll
		$a_01_3 = {57 45 20 53 49 4c 49 4e 45 45 2c 20 51 55 49 43 4b 45 52 2c } //1 WE SILINEE, QUICKER,
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}