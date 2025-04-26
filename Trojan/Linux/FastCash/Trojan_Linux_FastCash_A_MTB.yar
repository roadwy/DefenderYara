
rule Trojan_Linux_FastCash_A_MTB{
	meta:
		description = "Trojan:Linux/FastCash.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 8b 55 d0 48 8b 45 c0 48 01 d0 48 89 c6 48 8b 55 c8 48 8b 45 c0 48 01 d0 48 89 c1 48 8b 45 e0 48 89 c2 48 89 cf e8 e4 ?? ?? ?? 8b 45 bc 85 c0 7e ?? 48 8b 45 c8 48 2b 45 d0 48 89 45 e8 48 b8 ff ff ff 7f ff ff ff ff 48 39 45 e8 7e ?? b8 00 00 00 80 48 39 45 e8 } //1
		$a_03_1 = {55 48 89 e5 48 83 c4 80 48 89 7d a8 48 89 75 a0 48 89 55 98 48 89 4d ?? 44 89 45 8c 64 48 8b 04 25 28 00 00 00 48 89 45 f8 31 c0 48 c7 45 c0 00 00 00 00 48 8b 45 a8 48 89 45 c8 48 8b 45 a0 48 89 45 d0 48 8b 05 55 5e 00 00 48 8b 00 48 85 c0 74 ?? 48 8b 05 46 5e 00 00 48 8b 00 } //1
		$a_01_2 = {2f 6d 6e 74 2f 68 67 66 73 2f 4d 79 46 63 2f 4d 79 46 63 2f 73 75 62 68 6f 6f 6b 2f 73 75 62 68 6f 6f 6b 5f 78 38 36 2e 63 } //1 /mnt/hgfs/MyFc/MyFc/subhook/subhook_x86.c
		$a_01_3 = {2f 74 6d 70 2f 74 72 61 6e 73 2e 64 61 74 } //1 /tmp/trans.dat
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}