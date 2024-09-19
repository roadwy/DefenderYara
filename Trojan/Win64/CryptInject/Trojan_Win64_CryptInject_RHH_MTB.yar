
rule Trojan_Win64_CryptInject_RHH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.RHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 00 6e 00 68 00 61 00 6e 00 63 00 65 00 64 00 20 00 52 00 53 00 41 00 20 00 61 00 6e 00 64 00 20 00 41 00 45 00 53 00 } //1 Enhanced RSA and AES
		$a_01_1 = {2e 70 64 61 74 61 } //1 .pdata
		$a_03_2 = {50 45 00 00 64 86 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0c } //2
		$a_01_3 = {8b fa 41 fe c2 45 0f b6 c2 43 0f b6 14 08 44 02 da 41 0f b6 cb 42 8a 04 09 43 88 04 08 42 88 14 09 43 0f b6 0c 08 03 ca 0f b6 c1 42 8a 0c 08 30 0b 48 ff c3 48 ff cf 75 c9 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}