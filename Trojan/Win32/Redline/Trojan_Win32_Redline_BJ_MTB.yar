
rule Trojan_Win32_Redline_BJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 ea 8d 04 0a c1 f8 05 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 03 01 d0 8d 14 c5 00 00 00 00 01 d0 31 c3 89 d9 8b 55 f0 8b 45 0c 01 d0 89 ca 88 10 83 45 f0 01 8b 45 f0 3b 45 10 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}