
rule Trojan_Win32_Fragtor_ASGI_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ASGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {50 6a 40 68 90 01 02 00 00 57 ff 15 90 02 09 8d b5 90 01 02 ff ff 8b cf 2b f7 ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}