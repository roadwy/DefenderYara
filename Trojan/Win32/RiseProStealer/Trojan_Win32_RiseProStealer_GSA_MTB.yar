
rule Trojan_Win32_RiseProStealer_GSA_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.GSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 d1 e8 33 db 8a 5c 85 c8 8a 9b 90 01 04 30 5c 85 cc 33 db 8a 5c 85 c9 8a 9b 90 01 04 30 5c 85 cd 33 db 8a 5c 85 ca 8a 9b 14 b7 63 01 30 5c 85 ce 33 db 8a 5c 85 cb 8a 9b 14 b7 63 01 30 5c 85 cf 40 8b d9 4b 2b d8 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}