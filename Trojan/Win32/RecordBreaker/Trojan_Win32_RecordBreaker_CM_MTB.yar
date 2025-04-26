
rule Trojan_Win32_RecordBreaker_CM_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c7 d7 68 de 3a 8d 7f da 89 44 24 fc 83 ec 04 83 ec 04 89 34 24 83 ec 04 89 0c 24 89 44 24 fc 83 ec 04 60 8b 74 24 28 8b 7c 24 2c 8b 06 83 c6 04 89 44 24 1c 8b c8 c1 e9 02 83 e0 03 f3 a5 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}