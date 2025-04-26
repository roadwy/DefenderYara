
rule Trojan_Win32_Redline_GMV_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d8 88 45 d7 0f b6 4d d7 f7 d1 88 4d d7 0f b6 55 d7 f7 da 88 55 d7 0f b6 45 d7 03 45 d8 88 45 d7 0f b6 4d d7 f7 d9 88 4d d7 0f b6 55 d7 2b 55 d8 88 55 d7 8b 45 d8 8a 4d d7 88 4c 05 e8 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}