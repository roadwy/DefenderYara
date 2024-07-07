
rule Trojan_Win32_Barsebey_A{
	meta:
		description = "Trojan:Win32/Barsebey.A,SIGNATURE_TYPE_PEHSTR_EXT,ffffffcd 00 ffffffcc 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b6 fb 8b 55 fc 0f b6 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 45 fc 0f b6 44 38 ff } //100
		$a_01_1 = {32 33 43 35 38 44 31 38 36 45 34 31 36 44 34 41 38 44 35 31 38 41 33 41 37 33 45 31 43 37 41 38 33 46 36 41 36 43 46 38 36 37 39 44 44 35 30 44 43 45 39 41 41 43 30 45 43 34 } //102 23C58D186E416D4A8D518A3A73E1C7A83F6A6CF8679DD50DCE9AAC0EC4
		$a_01_2 = {6d 79 77 65 62 73 65 61 72 63 68 2e 63 6f 6d 2f 6a 73 70 2f 63 66 67 5f 72 65 64 69 72 32 } //1 mywebsearch.com/jsp/cfg_redir2
		$a_01_3 = {24 24 33 33 36 36 39 39 2e 62 61 74 } //1 $$336699.bat
		$a_01_4 = {63 6e 73 79 73 68 6f 73 74 } //1 cnsyshost
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*102+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=204
 
}