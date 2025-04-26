
rule Trojan_Win32_Redline_AAN_MTB{
	meta:
		description = "Trojan:Win32/Redline.AAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 33 d2 f7 75 10 8a 82 ?? ?? ?? ?? 32 c3 0f b6 1c 3e 8d 0c 18 88 0c 3e fe c9 88 0c 3e 6a 00 6a 00 ff 15 ?? ?? ?? ?? 28 1c 3e 6a 00 6a 00 ff 15 ?? ?? ?? ?? fe 04 3e 46 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}