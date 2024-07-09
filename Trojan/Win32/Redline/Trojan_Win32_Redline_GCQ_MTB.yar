
rule Trojan_Win32_Redline_GCQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 02 88 45 fe 0f b6 4d fe 8b 45 f8 33 d2 be 04 00 00 00 f7 f6 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 0c 03 45 f8 8a 08 88 4d fd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}