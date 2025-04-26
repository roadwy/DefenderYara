
rule Trojan_Win32_Redline_GJQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 bf 0f b6 4d bf 8b 45 c0 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d c7 8b 45 08 03 45 c0 8a 08 88 4d be 8a 55 be 88 55 bd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GJQ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e8 31 d2 f7 74 24 2c 8b 44 24 20 c1 ea ?? 0f be 0c 10 69 c9 ?? ?? ?? ?? 89 c8 f7 ef 8d 04 0a c1 f9 ?? ba ?? ?? ?? ?? c1 f8 ?? 29 c8 0f af c2 30 04 2b 83 c5 01 39 6c 24 ?? 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}