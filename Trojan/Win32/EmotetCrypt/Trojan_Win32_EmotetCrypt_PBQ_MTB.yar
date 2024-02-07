
rule Trojan_Win32_EmotetCrypt_PBQ_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 0f b6 04 0a 8b 54 24 90 01 01 32 44 1a 90 01 01 83 6c 24 90 01 01 01 88 43 90 00 } //01 00 
		$a_81_1 = {3c 36 54 75 36 78 4c 52 79 79 6e 74 6e 52 5f 68 5f 3e 59 29 21 4e 66 71 5e 6e 47 4e 32 4d 28 43 52 4a 4b 54 5f 7a 70 58 77 4f 75 63 3c 48 76 58 5f 5f 74 62 24 44 64 31 53 2a 2a 6c 28 63 65 6d 2a 47 77 43 33 24 5f 21 39 3f 63 45 40 39 56 4a 46 65 32 79 32 } //01 00  <6Tu6xLRyyntnR_h_>Y)!Nfq^nGN2M(CRJKT_zpXwOuc<HvX__tb$Dd1S**l(cem*GwC3$_!9?cE@9VJFe2y2
		$a_81_2 = {66 47 62 4b 3e 51 4a 50 50 57 75 40 41 61 55 72 5f 7a 64 67 77 65 41 38 44 36 4b 39 24 3e 5a 42 55 31 63 6c 24 6a 37 30 76 4a 4c 4a 29 77 36 29 55 28 6f 39 63 3e 25 44 63 29 4a 21 52 34 4f 52 61 64 56 42 4a 73 44 29 61 4d } //00 00  fGbK>QJPPWu@AaUr_zdgweA8D6K9$>ZBU1cl$j70vJLJ)w6)U(o9c>%Dc)J!R4ORadVBJsD)aM
	condition:
		any of ($a_*)
 
}