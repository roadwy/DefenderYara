
rule Trojan_Win32_Startpage_SQ{
	meta:
		description = "Trojan:Win32/Startpage.SQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 08 40 84 c9 75 [0-05] 2b c2 50 [0-04] 68 ?? ?? ?? ?? 6a 01 56 68 ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 } //1
		$a_03_1 = {68 57 00 07 80 e8 ?? ?? ?? ?? 55 8b 6c ?? ?? 56 55 53 e8 ?? ?? ?? ?? 8b f0 8b 07 8b 50 f8 83 e8 10 } //1
		$a_00_2 = {69 6c 63 2e 6e 62 7a 2e 63 6f 2e 6b 72 2f 69 6e 73 74 61 6c 6c 2e 61 73 70 3f 69 64 3d 31 38 36 26 6d 61 63 3d 25 73 } //1 ilc.nbz.co.kr/install.asp?id=186&mac=%s
		$a_00_3 = {64 69 73 6b 6d 61 6e 69 61 2e 63 6f 2e 6b 72 2f 70 72 6f 67 72 61 6d 2f 79 61 68 6f 6f 5f } //1 diskmania.co.kr/program/yahoo_
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}