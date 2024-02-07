
rule Trojan_Win32_Emotet_PAE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 33 5b 34 5d 35 6d 6d 5d 35 5c 5d 6d 5d 6d 6d 35 5c 6d 6d 35 35 35 35 35 35 35 5c 5c 5c 35 5c 5c 5c 35 6d 5c 35 35 5c 5c 35 65 64 } //01 00  63[4]5mm]5\]m]mm5\mm5555555\\\5\\\5m\55\\5ed
		$a_01_1 = {63 4f 58 59 2f 50 2e 5a 30 2e 30 2e 51 52 30 30 2f 5a 50 50 30 30 30 30 30 30 30 2f 30 50 50 5a 52 2e 42 49 40 2f 44 45 30 } //03 00  cOXY/P.Z0.0.QR00/ZPP0000000/0PPZR.BI@/DE0
		$a_03_2 = {03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 30 55 90 01 01 83 6c 24 90 01 01 01 75 90 01 01 8a 4c 24 90 01 01 8b 44 24 90 01 01 8a 54 24 90 01 01 5f 5e 5d 88 50 01 88 08 5b 83 c4 90 01 01 c3 90 00 } //00 00 
		$a_00_3 = {5d 04 00 } //00 f2 
	condition:
		any of ($a_*)
 
}