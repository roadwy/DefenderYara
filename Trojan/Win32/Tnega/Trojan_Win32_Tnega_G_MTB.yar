
rule Trojan_Win32_Tnega_G_MTB{
	meta:
		description = "Trojan:Win32/Tnega.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {31 17 09 d9 81 c7 90 01 04 39 c7 75 ed 4e 81 eb 90 01 04 c3 09 db 21 c9 00 00 09 c1 43 39 fe 75 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}