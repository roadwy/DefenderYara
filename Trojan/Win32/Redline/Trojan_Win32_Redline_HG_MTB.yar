
rule Trojan_Win32_Redline_HG_MTB{
	meta:
		description = "Trojan:Win32/Redline.HG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 08 8b 55 f0 8b 45 0c 01 d0 0f b6 00 31 c8 88 45 ef 8b 55 f0 8b 45 0c 01 d0 0f b6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}