
rule Trojan_Win32_TrickBotCrypt_GT_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 0c 08 33 ca 8b 15 90 01 04 0f af 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 8b 35 90 01 04 0f af 35 90 01 04 0f af 35 90 01 04 8b 7d f4 2b 3d 90 01 04 2b 3d 90 01 04 03 fe 03 c7 2b 05 90 01 04 2b c2 8b 55 0c 88 0c 02 90 00 } //1
		$a_81_1 = {3e 58 2a 71 44 32 61 53 50 39 66 63 50 42 56 57 44 54 26 70 23 32 2b 62 49 6b 6e 67 62 4e 69 68 5e 65 30 75 77 44 3f 54 49 48 24 4f 72 6b 37 67 48 73 4e 45 74 59 5e 51 70 28 6b 69 37 50 79 76 26 73 37 64 46 24 4d 21 66 6c 36 38 76 59 4a 30 61 2a 68 5f 38 68 43 78 21 55 } //1 >X*qD2aSP9fcPBVWDT&p#2+bIkngbNih^e0uwD?TIH$Ork7gHsNEtY^Qp(ki7Pyv&s7dF$M!fl68vYJ0a*h_8hCx!U
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}