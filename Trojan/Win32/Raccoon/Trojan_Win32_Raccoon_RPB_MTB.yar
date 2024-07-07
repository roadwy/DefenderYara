
rule Trojan_Win32_Raccoon_RPB_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d0 8b 85 7c ff ff ff 89 04 0a b9 04 00 00 00 6b d1 00 8b 45 d0 8b 8d 7c ff ff ff 89 0c 10 ba 04 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}