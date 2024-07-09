
rule Trojan_Win32_Emotetcrypt_GN_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b df 0f af de 0f af de 8d 5c 0b ?? 0f af df 03 d5 03 d3 2b d0 8b 44 24 ?? 03 d6 03 d1 0f b6 0c 02 8b 44 24 ?? 30 08 8b 44 24 ?? 83 c0 01 3b 44 24 ?? 89 44 24 ?? 0f 82 } //1
		$a_81_1 = {4b 4a 2a 50 50 49 3e 21 33 40 33 33 48 25 36 3f 4e 33 78 3e 6f 3e 5e 38 74 33 23 51 39 24 63 76 4a 36 78 45 32 33 53 3f 21 43 45 26 50 79 77 61 28 36 5a 33 6c 30 61 42 52 4c 75 28 2b 58 54 3f 61 } //1 KJ*PPI>!3@33H%6?N3x>o>^8t3#Q9$cvJ6xE23S?!CE&Pywa(6Z3l0aBRLu(+XT?a
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}