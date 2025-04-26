
rule Trojan_Win64_CryptInject_GTA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 4c 03 c0 45 02 08 44 88 8c 24 ?? ?? ?? ?? 41 0f b6 10 41 0f b6 c1 0f b6 4c 04 30 41 88 08 0f b6 84 24 31 01 00 00 88 54 04 30 44 0f b6 8c 24 31 01 00 00 0f b6 94 24 30 01 00 00 42 0f b6 4c 0c 30 02 4c 14 30 0f b6 c1 0f b6 4c 04 30 42 32 4c 13 03 41 88 4a ff 48 83 ef 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}