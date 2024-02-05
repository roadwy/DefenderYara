
rule Trojan_Win32_CryptInject_RBA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {40 2e eb ed 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 c1 e8 90 01 01 89 45 90 01 01 c7 05 90 01 04 2e ce 50 91 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 81 3d 90 01 04 76 09 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}