
rule Trojan_Win32_Redline_JAN_MTB{
	meta:
		description = "Trojan:Win32/Redline.JAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b c6 33 d2 f7 75 10 8a 82 90 01 04 32 c3 8b 55 08 0f b6 1c 16 8d 0c 18 88 0c 16 fe c9 88 0c 16 6a 00 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}