
rule Trojan_Win32_Glupteba_PPC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 18 8b 44 24 18 89 44 24 1c 8b 54 24 1c 31 54 24 ?? 8b f3 c1 ee 05 03 74 24 34 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 06 ff 15 ?? ?? ?? ?? 8b 44 24 14 33 c6 89 44 24 14 50 8b c7 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}