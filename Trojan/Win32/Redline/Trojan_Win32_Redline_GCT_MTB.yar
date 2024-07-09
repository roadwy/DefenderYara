
rule Trojan_Win32_Redline_GCT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 10 6b c0 ?? 99 bf ?? ?? ?? ?? f7 ff 6b c0 ?? 33 f0 03 ce 8b 55 0c 03 55 f4 88 0a 0f be 45 f3 8b 4d 0c 03 4d f4 0f b6 11 2b d0 8b 45 0c 03 45 f4 88 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}