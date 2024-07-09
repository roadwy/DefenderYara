
rule Trojan_Win32_Emotetcrypt_RWB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {76 56 6a 51 4f 6b 50 4f 64 4b 3e 5e 46 4f 45 47 4b 6c 5e 30 51 40 7a 5f 6d 25 36 28 40 5a 76 75 65 46 5f 25 } //1 vVjQOkPOdK>^FOEGKl^0Q@z_m%6(@ZvueF_%
		$a_03_1 = {03 cf 03 ce 2b ca 8b 45 ?? 2b c8 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 ?? 8b 45 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotetcrypt_RWB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 30 00 00 8b 95 ?? ?? ?? ?? 52 6a 00 6a ff ff 15 } //1
		$a_80_1 = {28 52 30 3c 6d 3c 73 61 3f 68 25 32 78 43 6a 62 37 21 64 44 47 24 2a 65 34 2a 69 38 70 21 33 55 75 74 6d 2a 67 42 76 43 79 34 72 4d 64 72 33 46 7a 66 67 29 } //(R0<m<sa?h%2xCjb7!dDG$*e4*i8p!3Uutm*gBvCy4rMdr3Fzfg)  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}