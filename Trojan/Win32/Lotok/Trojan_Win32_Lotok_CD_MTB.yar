
rule Trojan_Win32_Lotok_CD_MTB{
	meta:
		description = "Trojan:Win32/Lotok.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 4b c6 45 f1 45 c6 45 f2 52 c6 45 f3 4e c6 45 f4 45 c6 45 f5 4c c6 45 f6 33 c6 45 f7 32 c6 45 f8 2e c6 45 f9 64 c6 45 fa 6c c6 45 fb 6c c6 45 fc 00 c6 45 e0 56 c6 45 e1 69 c6 45 e2 72 c6 45 e3 74 c6 45 e4 75 c6 45 e5 61 c6 45 e6 6c c6 45 e7 41 c6 45 e8 6c c6 45 e9 6c c6 45 ea 6f c6 45 eb 63 c6 45 ec 00 8d 45 e0 50 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}