
rule Trojan_Win32_ClipBanker_DK_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 04 39 8d 49 01 2c 02 88 41 ff 83 eb 01 75 } //1
		$a_01_1 = {62 32 33 35 37 32 33 32 2d 35 32 62 30 2d 34 39 32 66 2d 62 32 36 66 2d 30 64 33 36 63 37 66 30 39 36 61 64 } //1 b2357232-52b0-492f-b26f-0d36c7f096ad
		$a_01_2 = {64 62 61 36 39 32 31 31 37 62 65 37 62 36 64 33 34 38 30 66 65 35 32 32 30 66 64 64 35 38 62 33 38 62 66 2e 78 79 7a 2f 41 50 49 2f 32 2f 63 6f 6e 66 69 67 75 72 65 2e 70 68 70 3f } //2 dba692117be7b6d3480fe5220fdd58b38bf.xyz/API/2/configure.php?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}