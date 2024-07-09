
rule Trojan_Win32_Emotetcrypt_II_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.II!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 28 bf ?? ?? ?? ?? 8b 44 24 24 0f be 1c 08 8b 44 24 20 0f b6 04 08 03 da 03 c3 99 8b df f7 fb 8b 5c 24 2c 8b 44 24 1c 8a 04 08 8a 1c 13 88 1c 0e 8b 5c 24 30 41 3b cf 88 04 13 } //1
		$a_81_1 = {35 6d 61 53 37 5a 30 5a 78 21 7a 36 6d 4a 79 35 66 66 23 29 40 24 2a 33 3f 30 71 45 71 33 28 76 41 42 49 52 71 65 48 42 21 33 43 50 6c 34 58 6a 43 54 74 58 51 5f 32 47 6b 61 42 3e 71 53 62 2a 48 4f 44 28 40 34 65 4c 51 5a 66 5f 42 4e 52 6c 70 66 77 67 37 55 31 40 68 45 36 } //1 5maS7Z0Zx!z6mJy5ff#)@$*3?0qEq3(vABIRqeHB!3CPl4XjCTtXQ_2GkaB>qSb*HOD(@4eLQZf_BNRlpfwg7U1@hE6
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}