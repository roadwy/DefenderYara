
rule Trojan_Win32_CryptInject_PH_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_02_0 = {55 8b 6c 24 1c 8b d7 2b ef 8d 04 2a 83 e0 3f 8a 80 90 01 04 32 44 0b 04 41 88 02 42 3b ce 72 90 00 } //01 00 
		$a_00_1 = {8b c1 99 f7 7c 24 20 8a 04 2a 8a 54 0f 08 32 c2 88 04 19 41 3b ce 7c e8 } //00 00 
	condition:
		any of ($a_*)
 
}