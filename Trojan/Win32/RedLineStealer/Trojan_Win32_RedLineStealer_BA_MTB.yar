
rule Trojan_Win32_RedLineStealer_BA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 be 04 00 00 00 f7 f6 a1 90 02 04 0f be 14 10 8b 45 f8 0f b6 0c 01 33 ca 8b 55 fc 8b 42 04 8b 55 f8 88 0c 10 eb 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}