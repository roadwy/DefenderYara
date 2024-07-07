
rule Trojan_Win32_Redline_WEB_MTB{
	meta:
		description = "Trojan:Win32/Redline.WEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f2 4b 88 55 87 0f b6 45 87 03 45 88 88 45 87 0f b6 4d 87 f7 d1 88 4d 87 0f b6 55 87 83 ea 2b 88 55 87 0f b6 45 87 33 45 88 88 45 87 8b 4d 88 8a 55 87 88 54 0d c8 e9 2e ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}