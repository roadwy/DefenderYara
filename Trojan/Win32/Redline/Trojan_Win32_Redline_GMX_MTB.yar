
rule Trojan_Win32_Redline_GMX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 83 f2 90 01 01 88 14 08 8d 0d 90 01 04 8d 05 90 01 04 89 0c 24 89 44 24 04 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}