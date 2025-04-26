
rule Trojan_Win32_Vidar_TOQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.TOQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 89 45 f4 8b 45 fc 8d 0c 03 33 d2 8b c3 f7 75 f4 8b 45 0c 57 8a 04 02 8b 55 f0 32 04 0a 88 01 ff d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}