
rule Trojan_Win32_IcedId_DBF_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {39 d8 7d 11 89 c2 40 f7 da 8a 54 11 ff 88 90 90 01 04 eb eb 90 00 } //01 00 
		$a_81_1 = {50 72 65 63 65 64 69 6e 67 20 77 69 74 68 20 7a 65 72 6f 73 3a 20 25 30 31 30 64 } //02 00  Preceding with zeros: %010d
		$a_81_2 = {24 7d 2a 74 6e 4b 45 50 47 46 48 42 4c 53 4f } //00 00  $}*tnKEPGFHBLSO
	condition:
		any of ($a_*)
 
}