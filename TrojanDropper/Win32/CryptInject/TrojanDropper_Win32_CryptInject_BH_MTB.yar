
rule TrojanDropper_Win32_CryptInject_BH_MTB{
	meta:
		description = "TrojanDropper:Win32/CryptInject.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8a 19 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 da 40 88 19 41 4e 75 } //2
		$a_01_1 = {66 89 54 24 0c 66 89 44 24 0e 66 89 74 24 10 66 89 74 24 14 66 89 4c 24 16 66 89 44 24 18 66 89 54 24 1a 66 89 44 24 1c 66 89 74 24 1e } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}