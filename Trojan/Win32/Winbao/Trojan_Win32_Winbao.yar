
rule Trojan_Win32_Winbao{
	meta:
		description = "Trojan:Win32/Winbao,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 73 74 61 72 77 77 73 6f 73 65 2e 63 6f 6d } //1 Mstarwwsose.com
		$a_01_1 = {73 74 61 72 73 73 73 70 72 6f 73 65 2e 63 6f 6d } //1 starsssprose.com
		$a_01_2 = {61 6f 62 61 6f 2e 63 } //1 aobao.c
		$a_01_3 = {2f 62 72 6f 77 73 65 2f 73 65 61 72 63 68 5f 61 75 63 74 69 6f 6e 2e 68 74 6d } //1 /browse/search_auction.htm
		$a_01_4 = {46 6f 72 63 65 52 65 6d 6f 76 65 20 7b 41 42 43 41 45 32 32 33 2d 31 32 37 38 2d 37 38 32 39 2d 41 34 33 45 2d 34 32 44 31 38 42 42 37 39 39 35 30 7d 20 3d 20 73 20 27 57 69 6e 64 6f 77 73 20 41 73 73 69 73 74 61 6e 6e 74 20 76 2e } //1 ForceRemove {ABCAE223-1278-7829-A43E-42D18BB79950} = s 'Windows Assistannt v.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}