
rule Trojan_Win32_Emotet_DG{
	meta:
		description = "Trojan:Win32/Emotet.DG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 18 8b 74 24 04 8a 1c 31 2a 1c 15 ?? ?? ?? ?? 8b 54 24 14 88 1c 32 } //1
		$a_00_1 = {8a 7d bf 2a 3c 32 00 df 8b 55 c0 01 d1 8b 75 e4 88 3c 16 83 c2 33 } //1
		$a_00_2 = {8a 24 0a 28 c4 01 ce 39 df 88 65 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}