
rule Trojan_Win32_Banbra_RPX_MTB{
	meta:
		description = "Trojan:Win32/Banbra.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c2 6a 00 ff ca fe c0 ff c9 ff c2 fe c2 ff c8 81 c1 ?? ?? 00 00 ff d7 ff c2 ff c9 fe cb fe c2 50 fe cb ff c8 03 c1 2b cb 81 f3 ?? ?? 00 00 33 d0 03 c1 fe ca } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}