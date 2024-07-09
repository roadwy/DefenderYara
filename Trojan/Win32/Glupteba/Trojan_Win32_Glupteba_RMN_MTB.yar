
rule Trojan_Win32_Glupteba_RMN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 [0-0c] 52 ef 6f 62 [0-02] 41 e5 64 03 [0-0c] 68 19 2a 14 [0-0c] be 08 9a 76 [0-0e] d3 e0 } //1
		$a_02_1 = {81 f3 07 eb dd 13 81 6d ?? ?? ?? ?? ?? 81 6d ?? ?? ?? ?? ?? 81 45 ?? ?? ?? ?? ?? 8b 45 ?? 5b 8b e5 } //1
		$a_02_2 = {8b ce c1 e1 04 03 8d ?? ?? ?? ?? 8b c6 c1 e8 05 03 85 ?? ?? ?? ?? 8d 14 37 33 ca 81 3d f4 1b 6c 04 72 07 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}