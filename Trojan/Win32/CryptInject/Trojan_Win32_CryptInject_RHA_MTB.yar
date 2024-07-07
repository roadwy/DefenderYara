
rule Trojan_Win32_CryptInject_RHA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {67 3d 3d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 00 e8 90 01 02 00 00 e9 ff 90 01 01 ff ff 02 90 00 } //2
		$a_03_1 = {66 8b c0 0f 31 52 8f 45 f0 50 8d 00 8f 45 14 bf 47 6b 01 90 01 6a 0f 31 8d 24 24 50 66 8b ff 8f 45 f4 8b 4d 14 8b 45 f4 3b c8 0f 84 69 ff ff ff 8b d0 33 d1 0f 84 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}