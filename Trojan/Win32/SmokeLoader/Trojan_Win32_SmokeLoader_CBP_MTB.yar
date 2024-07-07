
rule Trojan_Win32_SmokeLoader_CBP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 75 62 75 68 6f 78 6f 66 6f 6e 75 64 75 } //1 yubuhoxofonudu
		$a_01_1 = {79 61 72 6f 63 61 78 6f 72 65 6c 61 62 6f 6e 75 73 75 6b 65 76 69 66 61 70 69 70 } //1 yarocaxorelabonusukevifapip
		$a_01_2 = {74 75 73 65 62 75 76 6f 66 6f 6e 61 6b 75 72 6f 72 69 78 65 } //1 tusebuvofonakurorixe
		$a_01_3 = {7a 65 7a 61 66 65 78 6f 78 69 6a 61 77 75 6e 6f 6b 6f 66 75 66 65 } //1 zezafexoxijawunokofufe
		$a_01_4 = {72 61 70 6f 64 6f 67 61 67 61 } //1 rapodogaga
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}