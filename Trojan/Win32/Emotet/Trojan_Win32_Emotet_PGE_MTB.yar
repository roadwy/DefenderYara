
rule Trojan_Win32_Emotet_PGE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d0 89 15 88 7d 45 00 8b 0d 14 54 46 00 81 c1 fc 74 7d 01 89 0d 14 54 46 00 8b 15 10 54 46 00 03 55 ec a1 14 54 46 00 89 82 ef fa ff ff 8b 0d 90 7d 45 00 83 c1 3b 2b 0d 94 7d 45 00 89 4d f0 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}