
rule Trojan_Win64_Emotetcrypt_KZ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb ff c3 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 8b 05 ?? ?? ?? ?? 48 63 d1 0f b6 0c 02 32 4c 2f ff 88 4f ff 48 83 ee 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}