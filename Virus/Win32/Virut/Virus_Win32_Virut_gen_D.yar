
rule Virus_Win32_Virut_gen_D{
	meta:
		description = "Virus:Win32/Virut.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {cd 2e 85 c0 79 ec 55 e8 e1 ff ff ff 91 e8 db ff ff ff 83 c4 08 8b 54 24 04 2b c1 87 ea 81 6c 24 04 ?? ?? ?? 00 2d 80 01 00 00 73 bf 81 ed ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 66 8b 90 90 ?? ff ff ff e8 8f ff ff ff } //1
		$a_03_1 = {cd 2d eb 05 c1 e3 09 79 ef e8 eb ff ff ff 8b c8 e8 e4 ff ff ff f7 d9 55 8b 6c 24 04 03 c1 81 6c 24 04 ?? ?? ?? 00 2d 00 01 00 00 73 cb 81 ed ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 8a 90 90 ?? ff ff ff e8 a3 ff ff ff } //1
		$a_03_2 = {cd 2e 85 c0 79 ec 55 e8 e1 ff ff ff 91 e8 db ff ff ff 83 c4 08 8b 54 24 04 2b c1 87 ea 81 6c 24 04 ?? ?? ?? 00 2d 80 01 00 00 cc bf ?? ?? ?? ?? 30 00 8d 85 ?? ?? ?? ?? 66 8b 90 90 ?? ff ff ff e8 8f ff ff ff } //1
		$a_03_3 = {e8 27 00 00 00 81 c7 ?? ?? ?? ?? 29 d2 81 ca ?? ?? 00 00 bd ?? 00 00 00 57 8a 07 66 29 e8 86 07 83 c7 01 4a 83 fa 00 75 f0 5f ff e7 5f ff e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}