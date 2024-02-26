
rule Trojan_Win32_CryptInject_HN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.HN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2a 0f 82 06 90 01 03 8b 8d 90 01 04 0f 85 90 01 04 66 81 f1 90 01 02 b9 90 01 04 b8 90 01 04 05 90 01 04 bb 90 01 04 ba 90 01 04 81 ea 90 01 04 ed 81 fb 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}