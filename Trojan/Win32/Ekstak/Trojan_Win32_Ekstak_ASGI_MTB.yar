
rule Trojan_Win32_Ekstak_ASGI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ec c0 00 00 00 8d 44 24 04 56 50 ff 15 ?? ?? 64 00 8b 35 ?? ?? 64 00 6a 00 ff d6 83 f8 07 75 04 6a 01 ff d6 c7 44 24 04 00 00 00 00 ff 15 ?? ?? 64 00 85 c0 5e 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}