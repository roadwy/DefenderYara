
rule Trojan_Win32_Fareit_DRLO_MTB{
	meta:
		description = "Trojan:Win32/Fareit.DRLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 14 13 44 5b 14 13 4c 5b 14 13 54 5b 14 13 5c 5b 14 13 64 5b 14 13 6c 5b 14 13 74 5b 14 13 7c } //00 00 
	condition:
		any of ($a_*)
 
}