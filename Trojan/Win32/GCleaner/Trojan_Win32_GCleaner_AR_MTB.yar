
rule Trojan_Win32_GCleaner_AR_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 fe 81 ef ?? ?? 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3b 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc 72 } //4
		$a_01_1 = {33 c0 8b 55 ec 01 13 8b 75 d4 03 75 a4 03 75 ec 03 f0 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}