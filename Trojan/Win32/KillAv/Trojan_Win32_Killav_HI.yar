
rule Trojan_Win32_Killav_HI{
	meta:
		description = "Trojan:Win32/Killav.HI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b0 d4 b0 98 b0 37 b0 16 b0 38 b0 b1 b0 85 8b 45 08 03 45 f8 0f be 08 83 c1 20 8b 55 08 03 55 f8 88 0a } //1
		$a_01_1 = {b0 38 b0 b1 b0 85 c7 85 a0 fe ff ff 00 00 00 00 eb 0f 8b 95 a0 fe ff ff 83 c2 01 89 95 a0 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}