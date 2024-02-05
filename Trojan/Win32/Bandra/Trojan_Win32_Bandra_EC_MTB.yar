
rule Trojan_Win32_Bandra_EC_MTB{
	meta:
		description = "Trojan:Win32/Bandra.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 06 00 "
		
	strings :
		$a_01_0 = {89 84 95 10 f8 ff ff b9 04 00 00 00 6b d1 00 8b 45 fc 8b 4c 15 e8 89 8c 85 40 f0 ff ff ba 04 00 00 00 c1 e2 00 b8 04 00 00 00 6b c8 00 8b 54 15 f0 89 54 0d f0 } //01 00 
		$a_01_1 = {76 00 73 00 5f 00 63 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 74 00 79 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}