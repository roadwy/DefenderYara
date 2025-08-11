
rule Trojan_Win32_Neoreblamy_NFO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 58 6b c0 00 8b 84 05 24 fe ff ff 40 6a 04 59 6b c9 00 89 84 0d 24 fe ff ff 6a 04 58 6b c0 00 } //2
		$a_01_1 = {eb 07 8b 45 f0 48 89 45 f0 83 7d f0 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}