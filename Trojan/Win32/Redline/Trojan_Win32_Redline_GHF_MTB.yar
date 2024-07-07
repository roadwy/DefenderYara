
rule Trojan_Win32_Redline_GHF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 3e 8b c6 83 e0 03 ba 90 01 04 b9 90 01 04 8a 80 90 01 04 32 c3 02 c3 88 04 3e 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GHF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 90 01 01 0f be 4d 90 01 01 0f be 75 90 01 01 8b 45 90 01 01 99 bf 90 01 04 f7 ff 8b 45 90 01 01 0f be 14 10 69 d2 90 01 04 33 f2 03 ce 8b 45 90 01 01 03 45 90 01 01 88 08 0f be 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 2b c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}