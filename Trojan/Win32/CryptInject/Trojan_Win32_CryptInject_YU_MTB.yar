
rule Trojan_Win32_CryptInject_YU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 45 fc b8 90 01 02 00 00 e8 90 01 03 ff 8b 90 01 01 90 05 0a 01 90 33 90 01 01 90 05 0a 01 90 8b 90 02 0a 8a 90 01 04 00 90 05 0a 01 90 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}