
rule Trojan_Win32_EmotetCrypt_F_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8d 45 e8 ff 75 e8 50 56 6a 00 6a 01 6a 00 ff 75 d4 ff 15 ?? ?? ?? ?? 85 c0 74 1c ff 75 e8 8d 4d ef 56 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 8d 4d ef e8 ?? ?? ?? ?? ff d0 8b 4d fc 5f 33 cd 33 c0 5e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}