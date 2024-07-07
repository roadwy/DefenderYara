
rule Trojan_Win32_AveMaria_GHG_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 6a 64 99 5f f7 ff 8a 44 15 98 30 04 31 41 81 f9 00 78 05 00 7c e0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}