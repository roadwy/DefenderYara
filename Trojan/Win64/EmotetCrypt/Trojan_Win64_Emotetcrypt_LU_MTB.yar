
rule Trojan_Win64_Emotetcrypt_LU_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.LU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 1f 03 d0 41 8b c4 41 ff c4 6b d2 ?? 2b c2 42 8a 54 04 40 48 98 42 32 14 30 49 8b 90 09 06 00 41 ?? ?? c1 fa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}