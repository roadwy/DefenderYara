
rule Trojan_Win32_Redline_GCI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 29 c8 88 45 c3 8b 4d c4 0f b6 45 c3 01 c8 88 45 c3 0f b6 45 c3 83 f0 ff 88 45 c3 8b 4d c4 0f b6 45 c3 31 c8 88 45 c3 8b 4d c4 0f b6 45 c3 01 c8 88 45 c3 8a 4d c3 8b 45 c4 88 4c 05 c9 8b 45 c4 83 c0 01 89 45 c4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}