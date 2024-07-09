
rule Trojan_Win32_Redline_GES_MTB{
	meta:
		description = "Trojan:Win32/Redline.GES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 83 e0 03 8a 80 ?? ?? ?? ?? 32 04 1f 0f b6 0c 1f 8d 14 08 88 14 1f 2a d1 88 14 1f 43 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}