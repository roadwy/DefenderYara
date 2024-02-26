
rule Trojan_Win32_Amadey_AMBC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 31 45 f0 8b 45 f0 33 c2 2b f8 8b c7 c1 e0 04 89 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}