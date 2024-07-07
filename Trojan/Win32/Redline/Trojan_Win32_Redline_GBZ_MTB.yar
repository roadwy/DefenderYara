
rule Trojan_Win32_Redline_GBZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 8b 45 08 01 d0 0f b6 00 c1 e0 05 32 45 f3 89 c2 0f b6 45 f3 8d 0c 02 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 8b 55 f4 8b 45 0c 01 d0 0f b6 00 89 c2 0f b6 45 f3 89 d1 29 c1 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}