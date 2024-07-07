
rule Trojan_Win32_Emotetcrypt_IH_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 2c 0b 8b 44 24 28 0f be 04 08 03 ea 03 c5 99 8b ef f7 fd 8a 04 0e 8b 6c 24 18 88 44 24 13 8b 44 24 20 89 5c 24 2c 8a 5c 24 13 41 ff 44 24 18 3b cf 8a 04 10 88 45 00 8b 44 24 30 88 1c 10 } //1
		$a_81_1 = {33 62 5f 34 5e 77 3f 25 71 75 6b 44 64 75 52 30 50 26 4c 56 77 70 7a 56 5e 28 62 37 23 6f 31 7a 62 62 3f 3c 3e 28 21 78 3f 36 6c 34 69 51 54 39 7a 57 30 63 31 35 38 62 73 54 72 43 3e 63 4d 24 26 49 41 3f 71 57 78 42 66 7a 55 6f 54 5e 49 4e 64 42 24 6f } //1 3b_4^w?%qukDduR0P&LVwpzV^(b7#o1zbb?<>(!x?6l4iQT9zW0c158bsTrC>cM$&IA?qWxBfzUoT^INdB$o
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}