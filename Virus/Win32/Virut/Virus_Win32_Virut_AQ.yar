
rule Virus_Win32_Virut_AQ{
	meta:
		description = "Virus:Win32/Virut.AQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {fc e8 29 00 00 00 53 b9 a0 0d 00 00 8b da 66 31 10 40 86 d6 40 8d 14 13 e2 f4 5b c3 90 01 02 5d c3 0f 31 ff 24 24 55 b8 00 80 00 00 33 c9 eb 19 85 c0 75 06 cd 2e 85 c0 79 ec 55 e8 e1 ff ff ff 91 e8 db ff ff ff 83 c4 08 8b 54 24 04 2b c1 87 ea 81 6c 24 04 90 01 04 2d 80 01 00 00 73 bf 81 ed 06 10 30 00 8d 85 77 10 30 00 66 8b 90 90 a5 ff ff ff e8 8f ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}