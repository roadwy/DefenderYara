
rule Trojan_Win32_Fragtor_EN_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 85 c0 78 0a 83 f8 1a 7d 0a 83 c0 41 5d c3 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}