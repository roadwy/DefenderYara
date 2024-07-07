
rule Trojan_Win32_Emotetcrypt_DS_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 0f b6 44 85 90 01 01 8d 0c 19 30 03 8d 5b 04 b8 90 01 04 f7 e1 8b 4d f0 c1 ea 03 8d 04 52 c1 e0 02 2b f0 0f b6 44 b5 90 01 01 30 43 fd 8d 04 19 3d 00 38 02 00 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}