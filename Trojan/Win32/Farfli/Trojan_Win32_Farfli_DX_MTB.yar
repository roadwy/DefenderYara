
rule Trojan_Win32_Farfli_DX_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 75 73 65 72 73 2e 71 7a 6f 6e 65 2e 71 71 2e 63 6f 6d 2f 66 63 67 2d 62 69 6e 2f 63 67 69 5f 67 65 74 5f 70 6f 72 74 72 61 69 74 2e 66 63 67 3f } //http://users.qzone.qq.com/fcg-bin/cgi_get_portrait.fcg?  01 00 
		$a_80_1 = {44 55 42 2e 65 78 65 } //DUB.exe  01 00 
		$a_80_2 = {53 2e 65 78 65 } //S.exe  01 00 
		$a_80_3 = {59 59 2e 65 78 65 } //YY.exe  01 00 
		$a_80_4 = {56 33 53 76 63 2e 65 78 65 } //V3Svc.exe  01 00 
		$a_80_5 = {47 61 6d 65 20 4f 76 65 72 20 51 51 20 3a 20 34 36 34 38 31 35 30 } //Game Over QQ : 4648150  00 00 
	condition:
		any of ($a_*)
 
}