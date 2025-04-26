
rule Ransom_Win64_PrinceRansom_MX_MTB{
	meta:
		description = "Ransom:Win64/PrinceRansom.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 6e 63 65 2d 52 61 6e 73 6f 6d 77 61 72 65 } //1 Prince-Ransomware
		$a_01_1 = {47 6f 20 62 75 69 6c 64 } //1 Go build
		$a_01_2 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //1 EncryptDirectory
		$a_01_3 = {73 65 74 57 61 6c 6c 70 61 70 65 72 } //1 setWallpaper
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}