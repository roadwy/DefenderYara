
rule Trojan_Win32_Vidar_SRH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SRH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca 81 ea fb 07 82 d2 83 ea 01 81 c2 fb 07 82 d2 0f af ca 83 e1 01 83 f9 00 0f 94 c1 80 e1 01 88 4d e6 83 f8 0a 0f 9c c0 24 01 88 45 e7 c7 45 e0 90 01 04 8b 45 e0 89 45 d4 2d 0d 0d 8c 9d 0f 84 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}