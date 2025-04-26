
rule Trojan_Win32_GhostRat_RP_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {36 67 6b 49 42 66 6b 53 2b 71 59 3d } //1 6gkIBfkS+qY=
		$a_01_1 = {74 4e 43 32 70 67 3d 3d } //1 tNC2pg==
		$a_01_2 = {53 62 72 6a 61 72 20 4b 62 73 6b 62 } //1 Sbrjar Kbskb
		$a_01_3 = {47 77 6f 67 77 6f 20 48 78 66 77 6f 66 77 6f 20 51 78 6f 67 78 6f 67 78 20 50 68 78 70 } //1 Gwogwo Hxfwofwo Qxogxogx Phxp
		$a_01_4 = {44 74 6c 64 74 6c 63 74 20 4d 64 75 6d 64 75 6c 64 75 20 4d 65 76 6d 65 75 6d 20 46 76 6e 66 76 6e 65 76 20 4f 66 77 } //1 Dtldtlct Mdumduldu Mevmeum Fvnfvnev Ofw
		$a_01_5 = {32 36 36 62 35 34 37 63 63 30 61 64 34 38 61 34 34 63 31 38 30 33 34 36 66 64 35 61 34 36 31 39 } //1 266b547cc0ad48a44c180346fd5a4619
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}