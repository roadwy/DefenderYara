
rule Trojan_Win32_Vidar_VX_MTB{
	meta:
		description = "Trojan:Win32/Vidar.VX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 2a 32 14 18 88 13 ff d7 8b 5c 24 10 46 3b 74 24 20 72 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}