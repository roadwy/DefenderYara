
rule Trojan_Win32_Emotetcrypt_IP_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 28 03 c2 99 bd 90 01 04 f7 fd 8b 44 24 58 8b 6c 24 14 83 c5 01 89 6c 24 14 2b 54 24 18 2b d1 03 54 24 4c 03 54 24 50 03 d7 0f b6 14 02 8b 44 24 10 30 54 28 ff 90 00 } //1
		$a_81_1 = {55 26 53 63 6c 6f 6f 32 61 43 36 52 6e 4a 77 31 33 4a 42 69 44 4f 63 74 6a 74 72 52 5a 59 6e 45 79 72 50 55 2b 55 5e 70 41 } //1 U&Scloo2aC6RnJw13JBiDOctjtrRZYnEyrPU+U^pA
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}