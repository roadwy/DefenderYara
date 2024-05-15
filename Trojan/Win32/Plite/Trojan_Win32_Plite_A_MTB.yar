
rule Trojan_Win32_Plite_A_MTB{
	meta:
		description = "Trojan:Win32/Plite.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {88 14 0c 66 85 d7 8d ad 90 01 04 f8 80 d1 90 01 01 8b 4c 25 90 01 01 f5 f8 3b e3 33 cb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}