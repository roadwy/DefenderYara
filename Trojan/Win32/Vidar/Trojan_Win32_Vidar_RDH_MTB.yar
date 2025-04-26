
rule Trojan_Win32_Vidar_RDH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 2c 89 4c 24 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}