
rule Trojan_Win64_Emotet_PAW_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 41 89 09 c7 45 10 [0-04] 81 75 10 [0-04] 6b 45 10 [0-04] 89 45 10 c1 65 10 05 c1 6d 10 07 81 75 10 [0-04] 8b 45 10 89 45 10 8b 4d 28 8b 45 ?? 33 c8 41 89 0a c7 45 10 [0-04] 81 75 10 [0-04] c1 6d 10 04 81 75 10 [0-04] 8b 45 10 89 45 10 48 83 c4 ?? 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}