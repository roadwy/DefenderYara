
rule Trojan_Win32_Redline_GCZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 33 d2 b9 00 01 00 00 f7 f1 89 15 90 01 04 a1 90 01 04 0f b6 88 90 01 04 8b 15 90 01 04 0f b6 82 90 01 04 33 c1 8b 0d 90 01 04 88 81 90 01 04 8b 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}