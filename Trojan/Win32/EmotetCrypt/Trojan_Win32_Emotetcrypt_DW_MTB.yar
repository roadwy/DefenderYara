
rule Trojan_Win32_Emotetcrypt_DW_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 47 01 b8 ?? ?? ?? ?? 8b 4d ec 03 cf f7 e1 2b ca d1 e9 03 ca c1 e9 04 6b c1 13 8b 4d f8 2b f0 0f b6 84 b5 ?? ?? ?? ?? 30 47 02 83 c7 05 8d 04 0f 3d 00 30 02 00 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}