
rule Trojan_Win32_Emotetcrypt_FY_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 30 0f b6 0c 11 33 d2 03 c1 b9 ?? ?? ?? ?? f7 f1 8b 45 ?? 03 55 ?? 8b 4d ?? 0f b6 04 02 8b 55 ?? 30 04 0a 41 89 4d ?? 3b cf b9 ?? ?? ?? ?? 72 } //1
		$a_81_1 = {73 55 3f 6a 2b 42 55 23 58 46 36 7a 55 3c 25 45 5a 6f 30 47 28 73 64 31 51 75 3f 6d 47 54 57 76 29 64 2b 2b 4c 61 43 28 46 62 74 6d 4d 71 45 67 4a 49 28 33 25 76 28 28 35 49 65 6f 26 64 6d 6b 77 67 64 32 23 48 23 4a 73 79 29 70 77 47 77 4e 70 37 3f 3f 55 59 70 25 31 74 76 6c 56 6c 65 6f 69 55 50 41 64 47 32 54 57 62 31 75 } //1 sU?j+BU#XF6zU<%EZo0G(sd1Qu?mGTWv)d++LaC(FbtmMqEgJI(3%v((5Ieo&dmkwgd2#H#Jsy)pwGwNp7??UYp%1tvlVleoiUPAdG2TWb1u
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}