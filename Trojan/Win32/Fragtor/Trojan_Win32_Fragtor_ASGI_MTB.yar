
rule Trojan_Win32_Fragtor_ASGI_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ASGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 6a 40 68 ?? ?? 00 00 57 ff 15 [0-09] 8d b5 ?? ?? ff ff 8b cf 2b f7 ba } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}