
rule Trojan_Win32_Fragtor_AMAR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AMAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 14 b0 8b 44 24 ?? 81 c2 ?? ?? ?? ?? 8b 4c b0 ?? 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 02 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}