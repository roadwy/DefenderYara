
rule Trojan_Win32_Ekstak_ASDM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 ec 80 01 00 00 53 55 56 57 b9 45 00 00 00 33 c0 8d 7c 24 7c f3 ab 8d 44 24 7c c7 44 24 7c 14 01 00 00 50 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}