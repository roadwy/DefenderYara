
rule Trojan_BAT_Lazy_AYC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 63 39 fd 59 c3 7d 1a 1b c2 59 08 73 c9 51 a3 f6 09 6d 1e d2 9c f4 48 55 cb 10 d8 9e 8f 30 82 22 72 b8 a6 c4 e2 0a 6b 5b 87 13 8f c4 53 40 a5 8d 0d 09 4e 89 52 09 36 6e 5b ef b6 c3 e5 6d 48 24 70 6d 18 6a 97 99 c2 89 5d 3a 0a 95 31 1d cf f6 9d 66 c6 f9 33 } //5
		$a_01_1 = {24 64 64 33 66 64 64 39 63 2d 36 62 34 34 2d 34 64 37 33 2d 39 30 33 62 2d 37 36 36 61 62 64 31 62 33 34 38 64 } //2 $dd3fdd9c-6b44-4d73-903b-766abd1b348d
		$a_01_2 = {4b 69 6c 6c 55 6e 69 6e 73 74 61 6c 6c 54 6f 6f 6c } //1 KillUninstallTool
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=8
 
}