
rule Trojan_Win32_Growtopia_AMMB_MTB{
	meta:
		description = "Trojan:Win32/Growtopia.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 d0 c7 45 9c 90 01 04 89 44 24 08 c7 44 24 04 90 01 04 c7 04 24 90 01 04 e8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}