
rule Trojan_Win32_Redline_MKCY_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c3 33 c1 33 f0 89 4d ?? 89 45 ?? 89 75 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 56 8d 45 ?? 50 e8 } //1
		$a_03_1 = {01 45 fc 8b 45 ?? 8b 4d ?? 31 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}