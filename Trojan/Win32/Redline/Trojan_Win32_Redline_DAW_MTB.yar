
rule Trojan_Win32_Redline_DAW_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 10 8a 82 90 01 04 32 c3 0f b6 1c 3e 8d 0c 18 88 0c 3e fe c9 88 0c 3e 6a 00 6a 00 ff 15 90 00 } //1
		$a_03_1 = {59 28 1c 3e 6a 00 6a 00 ff 15 90 01 04 fe 04 3e 46 eb 90 00 } //1
		$a_01_2 = {76 6a 78 68 55 69 73 61 31 } //1 vjxhUisa1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}