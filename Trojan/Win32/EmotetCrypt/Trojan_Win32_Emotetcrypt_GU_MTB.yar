
rule Trojan_Win32_Emotetcrypt_GU_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2a 03 c2 99 bd ?? ?? ?? ?? f7 fd 8d 47 ?? 0f af 05 ?? ?? ?? ?? 40 0f af c7 8d 2c 76 2b c5 2b c1 83 e8 ?? 0f af c1 0f af cb 8b 6c 24 28 8d 4c 39 01 8d 4c 49 01 0f af cf 8b 3d ?? ?? ?? ?? 2b c1 8b 0d ?? ?? ?? ?? 03 c9 2b c1 8b 4c 24 ?? 03 c7 03 c6 03 d5 8a 14 42 8b 44 24 ?? 30 10 } //1
		$a_81_1 = {58 4e 31 5a 40 33 29 66 53 6d 6b 3c 62 43 36 2b 77 5a 78 38 33 2a 6f 62 31 45 5a 6c 42 25 5e 71 6c 38 48 4d 75 72 66 74 77 } //1 XN1Z@3)fSmk<bC6+wZx83*ob1EZlB%^ql8HMurftw
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}