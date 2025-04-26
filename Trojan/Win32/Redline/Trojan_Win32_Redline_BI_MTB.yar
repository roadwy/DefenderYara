
rule Trojan_Win32_Redline_BI_MTB{
	meta:
		description = "Trojan:Win32/Redline.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 e0 0f b6 82 [0-04] 33 c8 88 4d fb 8b 45 ec 8a 80 [0-04] 88 45 ea 8a 45 ea 88 45 e8 8b 45 ec 8a 80 [0-04] 88 45 e9 0f b6 45 e9 0f b6 4d fb 03 c1 89 45 dc 8b 45 ec 8a 4d dc 88 88 [0-04] 8b 45 ec 0f b6 80 [0-04] 0f b6 4d e8 2b c1 89 45 d8 8b 45 ec 8a 4d d8 88 88 [0-04] e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}