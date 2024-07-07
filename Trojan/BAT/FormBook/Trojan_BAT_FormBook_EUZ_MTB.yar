
rule Trojan_BAT_FormBook_EUZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 3f 4c 4d ee 32 2a cf fc c2 75 4c 67 74 7c 4e cb 71 0a da 4e 42 d9 3d 60 7b 5f 56 93 63 37 eb 31 53 10 15 9b 86 28 3a e2 c9 bb 4e 22 3c 6e 87 } //1
		$a_01_1 = {cc ca ba 4e 2d c1 a6 4d 3a cf 56 35 92 3b 37 d5 cd c6 c6 b2 30 3c 06 66 6a 49 24 c0 b8 41 31 ce ad 32 4c 39 cc c8 cb cd cb bc 3b 39 c5 c9 be 41 } //1
		$a_01_2 = {22 3c be 4c 3d c9 ac 3c 41 3a 36 cb ca cb cc bd 31 3c c6 c9 bb 4e 22 3c be 4c 3d c9 ac 3c 41 3a 36 cb ca cb cc bd 31 3c c6 c9 bb 4e 22 3c be 4c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}