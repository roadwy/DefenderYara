
rule Trojan_Win64_Emotetcrypt_NM_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 0f af c3 48 03 c5 44 32 44 04 30 49 8b c1 48 0f af c3 48 2b d0 49 8d 42 ?? 48 83 c2 ?? 49 0f af c3 49 0f af d1 48 2b d0 49 63 c5 48 0f af c8 48 8d 04 2a 48 ff c5 48 03 c8 48 03 cb 48 03 cf 46 88 04 39 } //1
		$a_01_1 = {7a 6f 23 49 3e 23 66 42 4e 39 54 40 32 6a 62 33 40 49 45 69 6e 56 32 74 7a 70 42 52 67 59 } //1 zo#I>#fBN9T@2jb3@IEinV2tzpBRgY
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}