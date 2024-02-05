
rule Trojan_Win32_Emotet_HC{
	meta:
		description = "Trojan:Win32/Emotet.HC,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 c1 8b c8 c1 e1 1f c1 f9 1f 8b f0 c1 e6 1d c1 fe 1f 81 e6 19 c4 6d 07 81 e1 96 30 07 77 33 ce 8b f0 c1 e6 19 c1 fe 1f 81 e6 90 41 dc 76 33 ce 8b f0 c1 e6 1a c1 fe 1f 81 e6 c8 20 6e 3b 33 ce 8b f0 c1 e6 1b c1 fe 1f 81 e6 64 10 b7 1d 33 ce 8b f0 c1 e6 1c c1 fe 1f 81 e6 32 88 db 0e 33 ce 8b f0 c1 ee 08 33 ce 8b f0 c1 e6 18 c1 e0 1e c1 fe 1f c1 f8 1f 81 e6 20 83 b8 ed 33 ce 25 2c 61 0e ee } //00 00 
	condition:
		any of ($a_*)
 
}