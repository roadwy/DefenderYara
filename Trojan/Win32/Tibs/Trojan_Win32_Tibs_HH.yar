
rule Trojan_Win32_Tibs_HH{
	meta:
		description = "Trojan:Win32/Tibs.HH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {87 02 83 ea fd 42 83 c1 fe 83 e9 02 85 c9 90 09 10 00 90 02 03 68 90 01 02 00 00 59 87 02 90 02 03 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}