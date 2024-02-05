
rule Trojan_Win32_Tofsee_RD_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 07 f7 d8 83 ef fc f7 d8 83 e8 29 83 e8 02 83 e8 ff 29 d0 50 5a 6a 00 8f 03 01 03 83 c3 04 83 ee fc 8d 05 f0 15 41 00 2d 65 98 00 00 ff e0 } //00 00 
	condition:
		any of ($a_*)
 
}