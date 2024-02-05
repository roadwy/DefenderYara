
rule Trojan_Win32_Phorpiex_RA_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 e8 90 01 04 99 b9 ff 7f 00 00 f7 f9 81 c2 e8 03 00 00 52 8d 95 90 01 02 ff ff 52 68 90 01 04 8d 85 90 01 02 ff ff 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}