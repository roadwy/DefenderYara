
rule Trojan_Win32_Vidar_EM_MTB{
	meta:
		description = "Trojan:Win32/Vidar.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f8 2b c1 8b c8 8b 45 fc 03 d0 89 55 f4 33 d2 f7 f1 8b 45 0c 57 8a 0c 02 8b 45 f4 8b 55 08 32 0c 02 88 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}