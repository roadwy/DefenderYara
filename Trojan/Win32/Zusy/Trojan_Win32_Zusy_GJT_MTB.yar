
rule Trojan_Win32_Zusy_GJT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 38 81 c3 90 01 04 81 c0 90 01 04 39 d0 75 90 01 01 c3 68 68 90 01 04 8d 3c 39 8b 3f 09 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}