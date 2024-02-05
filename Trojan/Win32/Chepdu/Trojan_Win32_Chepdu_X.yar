
rule Trojan_Win32_Chepdu_X{
	meta:
		description = "Trojan:Win32/Chepdu.X,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {35 82 00 00 76 90 14 4e 83 fe 00 77 90 01 01 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}