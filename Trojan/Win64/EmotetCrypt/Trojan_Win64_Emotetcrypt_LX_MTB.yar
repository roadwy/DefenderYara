
rule Trojan_Win64_Emotetcrypt_LX_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 ee c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c6 41 ff c6 8d 0c 92 c1 e1 ?? 2b c1 49 8b ca 48 98 46 32 0c 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}