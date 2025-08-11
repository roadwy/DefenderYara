
rule Trojan_Win32_DllInject_GVC_MTB{
	meta:
		description = "Trojan:Win32/DllInject.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 1c a1 ?? ?? ?? ?? 33 c5 89 45 fc 89 4d e8 c7 45 e4 0f 00 00 00 c6 45 ec c3 c6 45 ed 7e c6 45 ee 3b c6 45 ef 8f c6 45 f0 2c c6 45 f1 17 c6 45 f2 52 c6 45 f3 0c c6 45 f4 ef c6 45 f5 6f c6 45 f6 3b c6 45 f7 9d c6 45 f8 2b c6 45 f9 33 c6 45 fa 02 a1 ?? ?? ?? ?? 64 8b 0d 2c 00 00 00 8b 14 81 8b 82 2c 00 00 00 83 e0 01 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}