
rule Trojan_BAT_Taskun_ATA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ATA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 61 70 73 5f 52 6f 75 74 65 72 2e 44 61 6e 67 4e 68 61 70 } //1 Maps_Router.DangNhap
		$a_01_1 = {65 31 39 34 31 30 35 61 2d 62 30 34 65 2d 34 33 38 38 2d 38 31 63 39 2d 61 36 62 64 33 37 32 33 62 34 61 32 } //1 e194105a-b04e-4388-81c9-a6bd3723b4a2
		$a_01_2 = {37 33 45 45 42 43 42 46 30 46 33 34 41 42 44 31 33 37 39 38 38 44 44 30 39 38 41 43 42 36 30 42 39 46 38 39 42 46 30 32 36 38 30 44 30 32 33 41 37 45 31 38 32 30 38 44 45 35 35 34 43 35 37 39 } //1 73EEBCBF0F34ABD137988DD098ACB60B9F89BF02680D023A7E18208DE554C579
		$a_01_3 = {4d 61 70 73 5f 52 6f 75 74 65 72 2e 41 62 6f 75 74 42 6f 78 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Maps_Router.AboutBox1.resources
		$a_01_4 = {4d 61 70 73 5f 52 6f 75 74 65 72 2e 44 61 6e 67 4b 79 2e 72 65 73 6f 75 72 63 65 73 } //1 Maps_Router.DangKy.resources
		$a_01_5 = {4d 61 70 73 5f 52 6f 75 74 65 72 2e 4d 61 6e 48 69 6e 68 43 68 69 6e 68 2e 72 65 73 6f 75 72 63 65 73 } //1 Maps_Router.ManHinhChinh.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}