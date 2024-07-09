
rule Trojan_Win32_Emotet_DFV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8d 4c 24 14 c7 84 24 ?? ?? ?? ?? ff ff ff ff 8a 94 14 ?? ?? ?? ?? 32 da 88 5d 00 } //1
		$a_81_1 = {64 4e 4d 6f 34 56 71 67 70 72 6b 4d 63 51 48 69 32 72 35 33 5a 4c 51 4c 52 75 48 67 4f 53 33 45 6e 50 74 56 4c 65 } //1 dNMo4VqgprkMcQHi2r53ZLQLRuHgOS3EnPtVLe
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}