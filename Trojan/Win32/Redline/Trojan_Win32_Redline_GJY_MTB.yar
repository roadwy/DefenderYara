
rule Trojan_Win32_Redline_GJY_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 45 bb 8b 45 bc 33 d2 f7 75 ac 0f b6 8a ?? ?? ?? ?? 0f b6 55 bb 33 d1 88 55 eb 8b 45 bc 8a 88 ?? ?? ?? ?? 88 4d ba 31 d2 89 55 a8 8b 45 a8 89 45 e4 0f b6 4d eb 8b 55 bc 0f b6 82 ?? ?? ?? ?? 03 c1 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-20] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}