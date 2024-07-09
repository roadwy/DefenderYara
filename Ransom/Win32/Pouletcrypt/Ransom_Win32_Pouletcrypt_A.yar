
rule Ransom_Win32_Pouletcrypt_A{
	meta:
		description = "Ransom:Win32/Pouletcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 6f 66 74 77 61 72 65 00 00 00 00 ff ff ff ff ?? 00 00 00 [0-10] 00 00 ff ff ff ff ?? 00 00 00 52 61 7a 64 31 [0-08] 00 00 ff ff ff ff } //1
		$a_02_1 = {b9 01 00 00 00 e8 ?? ?? ?? ff ff 0d ?? ?? ?? 00 8b ?? 8b 15 ?? ?? ?? 00 80 7c 10 ff 21 74 d6 [0-30] 85 c0 7e 17 ba 01 00 00 00 8b 0d ?? ?? ?? 00 80 7c 11 ff 2f 75 01 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*2) >=3
 
}