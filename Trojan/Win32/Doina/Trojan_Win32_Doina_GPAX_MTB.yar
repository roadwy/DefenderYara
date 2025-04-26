
rule Trojan_Win32_Doina_GPAX_MTB{
	meta:
		description = "Trojan:Win32/Doina.GPAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 83 c0 01 89 45 e4 8b 4d e4 3b 4d f4 7d 18 8b 55 fc 8b 02 33 45 f8 8b 4d fc 89 01 8b 55 fc 83 c2 04 89 55 fc eb d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}