
rule Trojan_Win32_Glupteba_PIB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 8b 44 24 24 01 44 24 10 03 de 31 5c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 81 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}