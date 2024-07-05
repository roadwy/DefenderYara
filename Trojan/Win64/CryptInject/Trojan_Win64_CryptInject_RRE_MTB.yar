
rule Trojan_Win64_CryptInject_RRE_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.RRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 2b c1 49 63 ca 48 8b c6 41 ff c2 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 48 2b c8 0f b6 44 0c 90 01 01 41 30 04 28 41 0f b6 09 b8 af 07 00 00 41 0f af ca 2b c1 44 3b d0 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}