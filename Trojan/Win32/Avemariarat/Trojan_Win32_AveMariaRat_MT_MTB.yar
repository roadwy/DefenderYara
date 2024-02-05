
rule Trojan_Win32_AveMariaRat_MT_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 51 ff 15 90 01 04 89 c3 6a 00 50 ff 15 90 0a 30 00 c6 84 10 90 01 05 42 75 90 01 01 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}