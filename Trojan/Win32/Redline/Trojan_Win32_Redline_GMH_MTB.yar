
rule Trojan_Win32_Redline_GMH_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 e4 8a 02 88 45 ee 0f b6 4d ee 8b 45 e4 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ef 68 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GMH_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f3 33 db 8b f6 8b f3 f6 17 33 c6 8b de 8b c0 80 07 ?? 8b c6 8b c0 8b db 80 2f ?? 33 c6 33 c3 33 db f6 2f 47 e2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GMH_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 6d 6d } //1 Nomm
		$a_01_1 = {5a 41 74 67 72 6a 74 79 75 6a 74 79 75 } //1 ZAtgrjtyujtyu
		$a_03_2 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-20] 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}