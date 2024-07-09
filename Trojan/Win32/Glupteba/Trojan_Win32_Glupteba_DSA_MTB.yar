
rule Trojan_Win32_Glupteba_DSA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 44 24 ?? 8c eb 73 22 8b 4c 24 ?? 8b c7 d3 e0 8b cf c1 e9 05 03 4c 24 20 03 44 24 ?? 89 15 ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 cf 33 c1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}