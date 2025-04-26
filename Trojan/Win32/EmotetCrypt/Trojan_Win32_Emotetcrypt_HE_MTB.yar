
rule Trojan_Win32_Emotetcrypt_HE_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 0a 03 c2 99 b9 ?? ?? ?? ?? f7 f9 a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 2b c8 0f af ce 03 c0 2b c5 03 d1 8d 0c 42 8b 54 24 20 8b 44 24 2c 83 c2 02 0f af 15 ?? ?? ?? ?? 2b ca 03 cf 03 cb 8a 0c 01 8b 44 24 24 30 08 } //1
		$a_81_1 = {78 75 41 45 3c 6b 57 64 6c 79 43 2a 69 33 56 73 49 52 59 76 40 59 48 4e 67 6b 34 68 59 35 47 42 70 30 55 68 4a 35 5a 72 6d 77 4a 5f 4f 6d 42 54 68 40 34 31 66 44 } //1 xuAE<kWdlyC*i3VsIRYv@YHNgk4hY5GBp0UhJ5ZrmwJ_OmBTh@41fD
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}