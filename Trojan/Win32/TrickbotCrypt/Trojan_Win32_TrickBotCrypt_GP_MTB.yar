
rule Trojan_Win32_TrickBotCrypt_GP_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 02 8b 45 90 01 01 0f b6 12 03 d8 0f b6 06 03 c2 99 be 90 01 04 f7 fe 0f b6 c2 8a 04 08 30 03 ff 45 90 01 01 8b 45 90 01 01 3b 45 90 01 01 7c 90 00 } //01 00 
		$a_81_1 = {71 61 75 21 33 42 50 32 4e 5a 4a 39 39 6e 75 44 6a 23 62 5f 7a 30 28 4b 63 4a 69 49 59 44 6a 64 48 78 71 58 40 62 4c 4e 40 5a 49 31 54 28 55 51 51 68 63 25 63 68 4c 21 63 73 64 6b 61 69 72 53 33 50 48 59 43 } //00 00  qau!3BP2NZJ99nuDj#b_z0(KcJiIYDjdHxqX@bLN@ZI1T(UQQhc%chL!csdkairS3PHYC
	condition:
		any of ($a_*)
 
}