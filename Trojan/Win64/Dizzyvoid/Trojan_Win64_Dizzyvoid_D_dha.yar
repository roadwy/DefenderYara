
rule Trojan_Win64_Dizzyvoid_D_dha{
	meta:
		description = "Trojan:Win64/Dizzyvoid.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 61 62 62 64 64 67 67 68 68 6b 6b 6d 6d 6e 6e 70 70 73 73 75 75 76 76 79 79 7a 7a 7c 7c } //1 aabbddgghhkkmmnnppssuuvvyyzz||
		$a_01_1 = {47 6c 6f 62 61 6c 5c 72 75 6e 5f 25 64 } //1 Global\run_%d
		$a_01_2 = {6a 66 6b 64 6a 76 65 75 6a 76 70 64 66 6a 67 64 33 34 3d 2d 33 32 31 } //1 jfkdjveujvpdfjgd34=-321
		$a_01_3 = {41 70 61 63 68 65 44 6f 46 69 6c 74 65 72 2e 64 6c 6c } //1 ApacheDoFilter.dll
		$a_01_4 = {53 74 61 72 74 57 6f 72 6b } //1 StartWork
		$a_01_5 = {61 70 72 5f 62 72 69 67 61 64 65 5f 63 72 65 61 74 65 } //1 apr_brigade_create
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}