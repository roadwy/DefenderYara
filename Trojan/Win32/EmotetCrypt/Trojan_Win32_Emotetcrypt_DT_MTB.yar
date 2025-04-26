
rule Trojan_Win32_Emotetcrypt_DT_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f0 0f b6 44 85 ?? 8d 0c 19 30 03 8d 5b 04 b8 ?? ?? ?? ?? f7 e1 8b 4d f8 c1 ea 03 8b c2 c1 e0 04 2b c2 2b f0 0f b6 44 b5 ?? 30 43 fd 8d 04 19 3d 00 38 02 00 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}