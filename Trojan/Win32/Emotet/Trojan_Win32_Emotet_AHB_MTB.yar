
rule Trojan_Win32_Emotet_AHB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 83 c1 02 89 4d e8 8b 55 e4 83 ea 01 89 55 e4 a1 ?? ?? ?? ?? 83 c0 02 0f b6 4d e4 2b c1 66 a3 } //3
		$a_03_1 = {81 c1 ef 35 01 00 2b 0d ?? ?? ?? ?? 03 4d e8 89 4d e8 8b 55 fc 8b 42 02 89 45 f0 8b 4d 0c 83 c1 3b } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}