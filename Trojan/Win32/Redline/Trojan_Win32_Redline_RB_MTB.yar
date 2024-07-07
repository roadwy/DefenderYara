
rule Trojan_Win32_Redline_RB_MTB{
	meta:
		description = "Trojan:Win32/Redline.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 ea 89 d0 c1 f8 04 89 ca c1 fa 1f 29 d0 6b d0 22 89 c8 29 d0 89 c2 8b 45 08 01 d0 0f b6 08 8b 55 f4 8b 45 0c 01 d0 0f b6 00 31 c8 88 45 f3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}