
rule Trojan_Win64_Stealerc_GPA_MTB{
	meta:
		description = "Trojan:Win64/Stealerc.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 45 42 57 5a 5a 6b 3c 75 43 45 42 59 5b 72 53 45 42 5f 58 57 42 5f 59 58 } //1 XEBWZZk<uCEBY[rSEB_XWB_YX
		$a_01_1 = {64 43 58 66 44 53 65 53 42 43 46 75 59 5b 5b 57 58 52 45 65 53 55 42 5f 59 58 3c } //1 dCXfDSeSBCFuY[[WXREeSUB_YX<
		$a_01_2 = {3c 6d 64 43 58 66 44 53 65 53 42 43 46 75 59 5b 5b 57 58 52 45 65 53 55 42 5f 59 58 6b 3c 64 73 66 7a 77 75 73 69 75 79 7b 7b 77 78 72 69 7a } //1 <mdCXfDSeSBCFuY[[WXREeSUB_YXk<dsfzwusiuy{{wxriz
		$a_01_3 = {78 73 3c 42 57 45 5d 5d 5f 5a 5a } //1 xs<BWE]]_ZZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}