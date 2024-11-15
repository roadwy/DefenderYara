
rule Trojan_Win32_Emotet_CCIM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CCIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c6 01 d6 81 c6 ?? ?? ?? ?? 8b 16 69 f1 ?? ?? ?? 00 01 f0 05 ?? ?? ?? ?? 33 10 03 54 24 6c 89 54 24 74 8b 44 24 74 } //2
		$a_03_1 = {8b 16 89 54 24 3c 69 54 24 2c ?? ?? ?? ?? 01 d0 05 b8 00 00 00 8b 00 89 c2 31 ca 8b 74 24 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}