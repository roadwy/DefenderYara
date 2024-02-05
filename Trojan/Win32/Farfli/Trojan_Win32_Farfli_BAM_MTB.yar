
rule Trojan_Win32_Farfli_BAM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 04 8d 84 24 34 01 00 00 50 8b 84 24 38 02 00 00 83 c0 08 50 ff b4 24 40 01 00 00 ff 15 90 02 04 8b 44 24 58 03 84 24 2c 01 00 00 89 84 24 38 02 00 00 8d 84 24 88 01 00 00 50 ff b4 24 38 01 00 00 ff 15 90 02 04 ff b4 24 34 01 00 00 ff 15 90 00 } //02 00 
		$a_01_1 = {2b f2 8b f8 8a 04 39 8d 49 01 34 51 88 41 ff 83 ee 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}