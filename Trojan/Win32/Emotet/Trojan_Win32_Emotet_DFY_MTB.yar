
rule Trojan_Win32_Emotet_DFY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 8a 84 34 ?? ?? ?? ?? 81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 00 8a 94 14 90 1b 00 32 c2 88 45 00 } //1
		$a_81_1 = {66 4e 46 4d 78 49 57 61 4a 46 31 48 69 42 4b 6e 49 48 76 48 45 35 5a 4c 4c 42 35 76 32 46 59 4a 41 54 79 57 32 } //1 fNFMxIWaJF1HiBKnIHvHE5ZLLB5v2FYJATyW2
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}