
rule Trojan_Win32_Neoreblamy_NW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {eb 07 83 a5 f4 fe ff ff 00 6a 04 58 6b c0 00 8b 44 05 fc } //2
		$a_01_1 = {eb 07 8b 45 94 40 89 45 94 83 7d 94 01 7d 0d 8b 45 94 } //1
		$a_03_2 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ff ff ff 8d 44 00 02 39 45 f4 } //1
		$a_01_3 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 03 7d 10 8b 45 c0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}