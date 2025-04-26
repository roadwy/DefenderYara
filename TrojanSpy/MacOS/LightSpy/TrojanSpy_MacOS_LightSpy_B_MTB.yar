
rule TrojanSpy_MacOS_LightSpy_B_MTB{
	meta:
		description = "TrojanSpy:MacOS/LightSpy.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 53 50 48 89 fb 48 83 c7 78 31 f6 e8 d1 7b 01 00 ?? ?? ?? ?? 31 f6 e8 c6 7b 01 00 ?? ?? ?? ?? 31 f6 e8 bb 7b 01 00 48 83 c3 10 48 89 df 31 f6 48 83 c4 08 5b 5d e9 a7 7b 01 00 } //1
		$a_01_1 = {41 56 53 48 89 fb 48 8b 35 94 02 02 00 4c 8b 35 a5 5a 01 00 41 ff d6 48 8b 35 5b 02 02 00 48 89 df 41 ff d6 48 8b 35 56 02 02 00 48 89 df 4c 89 f0 5b 41 5e 5d ff e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}