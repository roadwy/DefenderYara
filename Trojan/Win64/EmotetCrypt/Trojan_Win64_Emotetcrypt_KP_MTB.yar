
rule Trojan_Win64_Emotetcrypt_KP_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 c1 f8 90 01 01 89 d3 29 c3 89 d8 6b c0 90 01 01 89 ce 29 c6 89 f0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 90 01 04 01 8b 85 90 01 04 3b 85 90 01 04 0f 9c c0 84 c0 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}