
rule Trojan_Win32_Copak_GPA_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {64 8b 5d 00 90 02 30 31 90 02 3f ff 00 00 00 90 02 5f 81 90 01 01 f4 01 00 00 75 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}