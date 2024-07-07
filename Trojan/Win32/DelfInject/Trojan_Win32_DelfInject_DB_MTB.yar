
rule Trojan_Win32_DelfInject_DB_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 b8 03 45 e8 89 45 b4 90 02 0f 8b 55 d8 03 55 b4 03 c2 8b 55 ec 31 02 90 02 0f 8b 55 e8 83 c2 04 03 c2 89 45 e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}