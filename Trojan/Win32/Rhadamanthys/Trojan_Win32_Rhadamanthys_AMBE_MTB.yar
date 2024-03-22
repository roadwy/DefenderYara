
rule Trojan_Win32_Rhadamanthys_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b d8 03 5d a4 6a 00 e8 90 01 04 2b d8 8b 45 d4 31 18 83 45 ec 04 c7 45 88 90 01 03 00 c7 45 88 90 01 03 00 6a 00 e8 90 01 04 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}