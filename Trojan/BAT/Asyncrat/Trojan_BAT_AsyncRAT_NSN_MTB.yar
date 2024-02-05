
rule Trojan_BAT_AsyncRAT_NSN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {5f e0 95 11 07 25 1a d3 58 13 07 4b 61 20 90 01 03 3d 58 9e 20 90 01 03 b8 38 90 01 03 ff 11 14 1e 11 14 1e 95 11 15 1e 95 58 90 00 } //01 00 
		$a_01_1 = {72 6b 78 6b 6b 66 6c 66 7a 68 65 6a 78 73 70 2e 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}