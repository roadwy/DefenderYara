
rule Virus_Win32_Neshta_C{
	meta:
		description = "Virus:Win32/Neshta.C,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {cf f0 fb e2 69 f2 e0 ed ed e5 20 f3 f1 69 ec 20 7e f6 69 ea e0 e2 fb ec 7e 20 e1 e5 eb e0 f0 f3 f1 5f ea 69 ec 20 e4 e7 ff f3 f7 e0 f2 e0 ec 2e 20 c0 eb ff ea f1 e0 ed e4 f0 20 d0 fb e3 ee f0 e0 e2 69 f7 2c 20 e2 e0 ec 20 f2 e0 ea f1 e0 ec e0 20 3a 29 20 c2 ee f1 e5 ed fc 20 2d 20 ea e5 ef f1 ea e0 ff 20 ef e0 f0 e0 2e 2e 2e 20 c0 eb } //01 00 
		$a_01_1 = {44 65 6c 70 68 69 2d 74 68 65 20 62 65 73 74 2e 20 46 75 63 6b 20 6f 66 66 20 61 6c 6c 20 74 68 65 20 72 65 73 74 2e 20 4e 65 73 68 74 61 20 31 2e 30 20 4d 61 64 65 20 69 6e 20 42 65 6c 61 72 75 73 2e } //01 00  Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus.
		$a_01_2 = {42 65 73 74 20 72 65 67 61 72 64 73 20 32 20 54 6f 6d 6d 79 20 53 61 6c 6f 2e 20 5b 4e 6f 76 2d 32 30 30 35 5d 20 79 6f 75 72 73 20 5b 44 7a 69 61 64 75 6c 6a 61 20 41 70 61 6e 61 73 5d } //00 00  Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]
	condition:
		any of ($a_*)
 
}