
rule Trojan_Win32_Emotet_RN_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RN!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b c6 c1 e0 1f c1 f8 1f 8b ce c1 e1 1d c1 f9 1f 81 e1 19 c4 6d 07 25 96 30 07 77 33 c1 8b d6 c1 e2 19 c1 fa 1f 8b ce c1 e1 1a c1 f9 1f 81 e2 90 41 dc 76 33 c2 81 e1 c8 20 6e 3b 33 c1 8b d6 c1 e2 1b 8b ce c1 e1 1c c1 fa 1f c1 f9 1f 81 e2 64 10 b7 1d 33 c2 81 e1 32 88 db 0e 33 c1 8b ce 8b d6 c1 e1 18 c1 e6 1e c1 ea 08 c1 f9 1f 33 c2 c1 fe 1f 81 e1 20 83 b8 ed 33 c1 81 e6 2c 61 0e ee 47 33 f0 0f b6 07 85 c0 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}