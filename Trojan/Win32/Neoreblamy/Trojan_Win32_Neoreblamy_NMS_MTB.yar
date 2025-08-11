
rule Trojan_Win32_Neoreblamy_NMS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 d8 40 89 45 d8 83 7d d8 03 7d 10 8b 45 d8 } //1
		$a_03_1 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 00 } //1
		$a_03_2 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ?? ff ff 8d 44 00 02 39 45 d0 75 15 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}