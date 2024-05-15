
rule Trojan_Win32_Copak_GPX_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {d8 85 40 00 90 02 30 31 90 02 3f ff 00 00 00 90 02 5f 81 90 01 01 f4 01 00 00 75 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}