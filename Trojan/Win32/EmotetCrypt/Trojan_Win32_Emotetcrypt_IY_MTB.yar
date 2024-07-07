
rule Trojan_Win32_Emotetcrypt_IY_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {29 29 61 32 49 76 78 56 4e 63 21 40 6e 79 2b 65 61 4e 4f 41 33 24 2b 2a 4d 35 41 61 3c 25 62 74 44 30 63 43 64 49 72 48 29 32 5f 30 3c 31 66 6b 67 78 23 34 5e 53 38 79 72 65 68 5a 24 3c 4e 29 6d 33 64 73 37 76 66 4a 6f 26 57 6d 51 51 40 29 68 24 55 6f 79 79 62 30 76 71 64 78 75 25 2a 34 24 51 } //1 ))a2IvxVNc!@ny+eaNOA3$+*M5Aa<%btD0cCdIrH)2_0<1fkgx#4^S8yrehZ$<N)m3ds7vfJo&WmQQ@)h$Uoyyb0vqdxu%*4$Q
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}