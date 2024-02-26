
rule Trojan_Win32_AutoitInject_GPA_MTB{
	meta:
		description = "Trojan:Win32/AutoitInject.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 23 05 58 45 20 11 32 54 23 05 58 45 20 11 32 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad 00 00 e1 bb 3a 21 a5 29 e3 ec e7 0b 98 2e 40 bd e1 9a } //02 00 
		$a_01_1 = {64 95 61 e7 b6 4d 74 f8 00 00 e5 1a 58 35 81 34 92 a0 6c ac 25 4b 12 38 cb 35 db 1f 22 fd 40 23 79 e0 20 ce ca ea 1e 0b 89 9f } //00 00 
	condition:
		any of ($a_*)
 
}