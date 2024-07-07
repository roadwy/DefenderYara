
rule Trojan_Win32_Windigo_AMMD_MTB{
	meta:
		description = "Trojan:Win32/Windigo.AMMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c7 d3 e8 03 c6 89 45 ec 33 45 e4 31 45 fc 8b 45 fc 29 45 f4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}