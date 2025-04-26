
rule Trojan_Win64_Emotetcrypt_LY_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c7 41 ff c7 8d 0c d2 48 8d 14 76 03 c9 2b c1 b9 ?? ?? ?? ?? 48 98 46 32 0c 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}