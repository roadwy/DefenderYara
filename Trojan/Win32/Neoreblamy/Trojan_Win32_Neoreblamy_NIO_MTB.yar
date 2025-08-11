
rule Trojan_Win32_Neoreblamy_NIO_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 d0 40 89 45 d0 83 7d d0 ?? 7d 0d 8b 45 d0 } //1
		$a_03_1 = {6a 04 58 6b c0 00 8b 44 05 f4 89 85 ?? ?? ff ff 8b 45 fc } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}