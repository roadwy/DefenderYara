
rule Trojan_Win32_Redline_GMR_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 55 c7 c1 e2 03 0b ca 88 4d c7 0f b6 45 c7 05 90 01 04 88 45 c7 0f b6 4d c7 f7 d9 88 4d c7 0f b6 55 c7 83 ea 71 88 55 c7 8b 45 c8 8a 4d c7 88 4c 05 d8 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}