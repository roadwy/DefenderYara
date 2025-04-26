
rule Trojan_Win32_Redline_GLA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 55 f0 0f b6 02 33 c1 8b 0d 98 5f 52 00 03 4d f0 88 01 eb 90 0a 32 00 0f b6 0d ?? ?? ?? ?? 8b 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}