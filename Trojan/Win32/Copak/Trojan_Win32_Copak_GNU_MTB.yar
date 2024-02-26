
rule Trojan_Win32_Copak_GNU_MTB{
	meta:
		description = "Trojan:Win32/Copak.GNU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 3a 81 c2 04 00 00 00 81 c1 90 01 04 41 39 da 90 01 02 09 c0 41 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}