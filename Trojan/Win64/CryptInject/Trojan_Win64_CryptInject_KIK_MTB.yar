
rule Trojan_Win64_CryptInject_KIK_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 ca 01 4b 90 01 01 41 8b 14 02 49 83 c2 90 01 01 8b 4b 90 01 01 8b 43 90 01 01 81 f1 90 01 04 0f af c1 48 63 4b 90 01 01 89 43 90 01 01 8b 43 90 01 01 31 43 90 01 01 0f b6 c2 0f b6 53 90 01 01 0f af d0 48 8b 83 90 01 04 88 14 01 ff 43 90 01 01 8b 4b 90 01 01 44 8b 83 90 00 } //01 00 
		$a_03_1 = {ff c8 01 83 90 01 04 8b 43 90 01 01 2d 90 01 04 0f af d0 8b 83 90 01 04 89 93 90 01 04 8b 4b 90 01 01 44 01 43 90 01 01 81 c1 90 01 04 03 ca 0f af ca 8b 93 90 01 04 2b c2 2d 90 01 04 31 43 90 01 01 89 8b 90 01 04 49 81 fa 90 01 04 0f 8c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}