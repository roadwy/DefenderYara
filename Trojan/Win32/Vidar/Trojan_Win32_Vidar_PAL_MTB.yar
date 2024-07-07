
rule Trojan_Win32_Vidar_PAL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 34 3b e8 90 01 04 8b c8 33 d2 8b c3 f7 f1 8b 85 90 01 04 8b 8d 90 01 04 8a 04 02 32 04 31 88 06 8d 85 f4 fd ff ff 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}