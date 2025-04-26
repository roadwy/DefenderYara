
rule Trojan_Win32_AveMaria_RPZ_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 90 33 c9 bf 64 00 00 00 0f 1f 00 8b c1 33 d2 f7 f7 8a 44 15 98 30 04 19 41 81 f9 00 78 05 00 7c ea 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}