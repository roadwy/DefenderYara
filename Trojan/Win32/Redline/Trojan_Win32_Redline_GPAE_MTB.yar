
rule Trojan_Win32_Redline_GPAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {18 00 00 80 b6 60 90 01 09 8b d8 8b 0b 8b 49 04 90 00 } //02 00 
		$a_03_1 = {13 00 00 80 86 60 90 01 04 46 81 fe 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}