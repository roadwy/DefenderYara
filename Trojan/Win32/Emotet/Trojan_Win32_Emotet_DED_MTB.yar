
rule Trojan_Win32_Emotet_DED_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 43 4d 0f 85 } //1
		$a_81_1 = {62 68 6d 57 63 72 71 33 30 33 72 49 45 51 4f 37 30 54 59 79 6a 61 64 56 70 6e 59 50 30 58 35 30 42 } //1 bhmWcrq303rIEQO70TYyjadVpnYP0X50B
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}