
rule Trojan_Win32_Donut_PAA_MTB{
	meta:
		description = "Trojan:Win32/Donut.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 4d 0c 39 c8 0f 83 3c 00 00 00 e9 0b 00 00 00 8b 45 fc 89 c1 40 89 45 fc eb e2 8b 45 fc 8b 4d 08 01 c1 8b 45 fc 89 4d f8 8b 4d 14 31 d2 f7 f1 8b 45 10 01 d0 8b 4d f8 0f b6 09 0f b6 10 31 d1 8b 45 f8 88 08 eb c9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}