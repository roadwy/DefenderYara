
rule Trojan_Win32_Redline_GMY_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d8 88 45 90 01 01 0f b6 4d 90 01 01 f7 d1 88 4d 90 01 01 0f b6 55 90 01 01 03 55 90 01 01 88 55 90 01 01 0f b6 45 90 01 01 f7 d0 88 45 90 01 01 0f b6 4d 90 01 01 03 4d 90 01 01 88 4d 90 01 01 8b 55 90 01 01 8a 45 90 01 01 88 44 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}