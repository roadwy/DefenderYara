
rule Trojan_Win32_Ekstak_ASEO_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 ec 10 8d 44 24 00 6a 00 50 6a 00 68 19 00 02 00 6a 00 6a 00 6a 00 68 90 01 03 00 68 02 00 00 80 ff 15 90 01 03 00 8b 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}