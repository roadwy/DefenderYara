
rule Trojan_Win64_Barys_NA_MTB{
	meta:
		description = "Trojan:Win64/Barys.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {48 8d 1d 3b b9 01 00 48 8d 3d 90 01 04 eb 12 48 8b 03 48 85 c0 74 06 ff 15 c4 50 00 00 48 83 c3 08 90 00 } //01 00 
		$a_01_1 = {67 7a 77 65 6f 78 } //00 00  gzweox
	condition:
		any of ($a_*)
 
}