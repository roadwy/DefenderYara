
rule Trojan_Win32_Cortheaper_A{
	meta:
		description = "Trojan:Win32/Cortheaper.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 00 64 00 5f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 68 00 74 00 6d 00 3f 00 70 00 69 00 64 00 3d 00 } //1 ad_search.htm?pid=
		$a_01_1 = {73 00 65 00 61 00 72 00 63 00 68 00 5f 00 61 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 68 00 74 00 6d 00 3f 00 61 00 74 00 5f 00 74 00 6f 00 70 00 73 00 65 00 61 00 72 00 63 00 68 00 3d 00 } //1 search_auction.htm?at_topsearch=
		$a_01_2 = {6f 00 6d 00 34 00 68 00 67 00 6f 00 64 00 74 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 34 00 30 00 2d 00 2d 00 63 00 6f 00 6d 00 6d 00 65 00 6e 00 64 00 2d 00 30 00 2d 00 61 00 6c 00 6c 00 2d 00 30 00 2e 00 74 00 78 00 74 00 00 00 } //2
		$a_01_3 = {72 00 65 00 72 00 5c 00 56 00 49 00 45 00 57 00 20 00 53 00 4f 00 55 00 52 00 43 00 45 00 20 00 45 00 44 00 49 00 54 00 4f 00 52 00 5c 00 45 00 44 00 49 00 54 00 4f 00 52 00 20 00 4e 00 41 00 4d 00 45 00 } //2 rer\VIEW SOURCE EDITOR\EDITOR NAME
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}