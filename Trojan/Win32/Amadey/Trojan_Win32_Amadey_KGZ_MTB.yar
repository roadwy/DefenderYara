
rule Trojan_Win32_Amadey_KGZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.KGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c5 c1 e8 05 89 44 24 14 8b 44 24 30 01 44 24 14 8d 04 2b 33 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c ba ?? ?? ?? ?? 8d 4c 24 18 e8 ?? ?? ?? ?? 4e 74 09 8b 5c 24 18 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}