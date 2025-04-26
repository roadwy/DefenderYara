
rule Trojan_Win32_Oficla_C{
	meta:
		description = "Trojan:Win32/Oficla.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 4b 01 ba 01 00 00 00 30 03 0f b6 82 ?? ?? ?? ?? 83 c2 01 30 01 83 c1 01 83 fa 10 75 ec 83 c3 10 81 fb ?? ?? ?? ?? 75 d0 } //1
		$a_03_1 = {e9 7c fe ff ff c7 04 24 ?? ?? ?? ?? e8 ?? ?? 00 00 83 ec 04 83 f8 09 0f 8f 5a fd ff ff e9 5f fe ff ff } //1
		$a_03_2 = {ba 2f bf b5 98 c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? 89 c1 33 4d f0 81 c9 00 00 00 80 89 c8 f7 e2 c1 ea 1d } //1
		$a_01_3 = {43 3a 5c 00 25 75 00 00 00 00 47 45 54 20 2f 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}