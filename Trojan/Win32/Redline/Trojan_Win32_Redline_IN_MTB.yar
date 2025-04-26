
rule Trojan_Win32_Redline_IN_MTB{
	meta:
		description = "Trojan:Win32/Redline.IN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 3b 45 0c 73 2d 8b 55 08 8b 45 f8 01 d0 0f b6 08 8b 45 f8 83 e0 03 89 c2 8b 45 10 01 d0 0f b6 10 8b 5d 08 8b 45 f8 01 d8 31 ca 88 10 83 45 f8 01 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}