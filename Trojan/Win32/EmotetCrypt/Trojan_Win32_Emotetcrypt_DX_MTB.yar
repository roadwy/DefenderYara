
rule Trojan_Win32_Emotetcrypt_DX_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 44 05 d8 32 04 0e 88 01 8d 04 0b 83 e0 1f 0f b6 44 05 d8 32 42 fb 88 41 01 8b 45 cc 03 c1 83 e0 1f 0f b6 44 05 d8 32 42 fc 88 41 02 8b 45 c8 03 c1 83 e0 1f 0f b6 44 05 d8 32 42 fd 88 41 03 8d 04 17 83 c1 04 3d 00 32 02 00 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}