
rule Trojan_Win32_Emotetcrypt_RM_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e2 07 03 c2 8b c8 c1 f9 03 69 c9 b4 00 00 00 8b c7 2b c1 03 c6 8a c8 32 8d ?? ?? ?? ?? 85 db 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_RM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e6 02 0b d6 52 ff 74 24 ?? 53 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 f7 d8 50 ff 15 ?? ?? ?? ?? e9 } //1
		$a_80_1 = {3c 68 78 41 77 65 49 5f 5a 54 6f 4e 50 5a 32 44 24 23 41 61 75 5e 62 32 2b 39 6d 62 38 59 29 40 33 65 74 43 43 61 3f 45 4f 47 2a 33 72 54 79 37 64 59 62 51 4a 55 61 58 5e 5f 64 68 24 72 4e 26 25 6d 50 62 43 34 57 21 63 4a 26 4d 3f 3c 73 77 56 61 53 29 52 31 67 4b 38 34 34 71 66 62 2a 71 26 4a 64 34 49 6e 53 70 50 4d 66 37 41 23 24 } //<hxAweI_ZToNPZ2D$#Aau^b2+9mb8Y)@3etCCa?EOG*3rTy7dYbQJUaX^_dh$rN&%mPbC4W!cJ&M?<swVaS)R1gK844qfb*q&Jd4InSpPMf7A#$  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}