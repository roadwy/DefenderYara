
rule Trojan_Win32_Gozi_NW_MTB{
	meta:
		description = "Trojan:Win32/Gozi.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 43 20 80 fb 61 0f b6 c8 8d 76 01 0f b6 c3 8a 1e 0f 4d c8 69 d2 01 01 00 00 0f be c1 03 d0 c1 e0 10 33 d0 84 db } //00 00 
	condition:
		any of ($a_*)
 
}