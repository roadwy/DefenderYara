
rule Trojan_Win32_CryptInject_PVE_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b7 0c 50 0f be 55 87 0f af 55 bc 0f be 45 87 8b 75 bc 2b f0 33 d6 03 ca 8b 15 90 01 04 03 95 7c ff ff ff 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}