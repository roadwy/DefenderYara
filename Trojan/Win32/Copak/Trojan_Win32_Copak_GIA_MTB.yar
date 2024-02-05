
rule Trojan_Win32_Copak_GIA_MTB{
	meta:
		description = "Trojan:Win32/Copak.GIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {5a 31 38 81 c2 01 00 00 00 21 db 40 01 d3 81 eb 90 01 04 39 c8 75 cd c3 01 db 8d 3c 3e 81 c3 90 01 04 01 d2 8b 3f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}