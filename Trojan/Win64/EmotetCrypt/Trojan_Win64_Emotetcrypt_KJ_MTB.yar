
rule Trojan_Win64_Emotetcrypt_KJ_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 ca 48 6b c9 ?? 49 03 c9 0f b6 4c 01 ?? b8 ?? ?? ?? ?? 41 32 4c 33 ?? 41 f7 e8 88 4e ?? c1 fa ?? 8b c2 c1 e8 ?? 03 d0 48 8b 05 ?? ?? ?? ?? 48 63 ca 48 6b c9 ?? 49 03 c9 0f b6 4c 01 ?? 32 4c 37 ?? 49 83 ec ?? 88 4e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}