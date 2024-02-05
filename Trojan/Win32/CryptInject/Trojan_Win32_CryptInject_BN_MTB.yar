
rule Trojan_Win32_CryptInject_BN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 44 04 08 40 3d 90 01 02 00 00 72 f4 90 00 } //01 00 
		$a_02_1 = {0f b6 44 34 14 0f b6 d3 03 c2 99 b9 90 01 02 00 00 f7 f9 45 0f b6 54 14 14 30 55 ff 83 bc 24 50 0c 00 00 00 75 90 00 } //01 00 
		$a_00_2 = {83 c4 1c ff d6 5f 5e 5d b0 01 5b 59 c3 } //00 00 
	condition:
		any of ($a_*)
 
}