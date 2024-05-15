
rule Trojan_Win64_CryptInject_SCH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.SCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 ca 89 d2 0f b6 ca 48 8b 55 90 01 01 48 01 ca 0f b6 12 44 31 c2 88 10 8b 45 20 8d 50 ff 89 55 20 85 c0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}