
rule Trojan_Win32_Redline_RPW_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 07 9f fe 07 47 e2 f6 5f 5e 5b 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_RPW_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bf 1d 00 00 00 f7 ff 83 e0 4a 33 f0 03 ce 8b 55 0c 03 55 f8 88 0a 0f be 45 f7 8b 4d 0c 03 4d f8 0f b6 11 2b d0 8b 45 0c 03 45 f8 88 10 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}