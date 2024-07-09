
rule Trojan_Win32_Glupteba_GM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 7c 24 60 89 5c 24 14 81 f3 07 eb dd 13 81 6c 24 14 ?? ?? ?? ?? b8 41 e5 64 03 81 6c 24 14 ?? ?? ?? ?? 81 44 24 14 ?? ?? ?? ?? 8b 4c 24 14 8b 44 24 10 03 44 24 60 8b f7 d3 e7 c1 ee ?? 03 74 24 ?? 03 7c 24 ?? 33 f8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}