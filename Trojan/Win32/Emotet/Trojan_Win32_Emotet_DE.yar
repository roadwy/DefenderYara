
rule Trojan_Win32_Emotet_DE{
	meta:
		description = "Trojan:Win32/Emotet.DE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 20 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 55 77 6b 69 39 79 43 31 41 78 2e 70 64 62 } //01 00  -Uwki9yC1Ax.pdb
		$a_01_1 = {33 37 37 34 33 5f 64 76 64 61 64 6f 70 77 2b 2e 70 64 62 } //01 00  37743_dvdadopw+.pdb
		$a_01_2 = {5f 45 49 7a 79 52 51 6d 38 73 49 2e 4e 65 39 38 50 52 6c 47 54 75 56 6e 6f 6c 2e 70 64 62 } //01 00  _EIzyRQm8sI.Ne98PRlGTuVnol.pdb
		$a_01_3 = {62 65 72 4a 52 57 65 68 77 62 65 6e 45 54 4d 42 77 76 65 76 33 32 34 59 31 32 33 72 46 47 42 45 2e 50 64 62 } //01 00  berJRWehwbenETMBwvev324Y123rFGBE.Pdb
		$a_01_4 = {42 49 32 41 48 2e 70 64 62 } //01 00  BI2AH.pdb
		$a_01_5 = {42 55 34 32 34 41 44 5a 2b 65 37 53 51 47 6b 50 46 30 5f 65 73 74 64 75 6e 6d 6b 49 2e 70 64 62 } //01 00  BU424ADZ+e7SQGkPF0_estdunmkI.pdb
		$a_01_6 = {63 3a 5c 63 6f 6e 73 6f 6e 61 6e 74 5c 53 74 65 65 6c 5c 70 6f 73 74 54 6f 6c 64 2e 70 64 62 } //01 00  c:\consonant\Steel\postTold.pdb
		$a_01_7 = {63 3a 5c 65 6c 65 63 74 72 69 63 5c 72 61 64 69 6f 5c 70 72 6f 62 6c 65 6d 5c 77 68 6f 73 65 62 75 74 2e 70 64 62 } //01 00  c:\electric\radio\problem\whosebut.pdb
		$a_01_8 = {63 3a 5c 4f 66 74 65 6e 5c 46 6f 75 72 5c 64 69 72 65 63 74 5c 44 69 76 69 73 69 6f 6e 74 65 6e 2e 70 64 62 } //01 00  c:\Often\Four\direct\Divisionten.pdb
		$a_01_9 = {63 3a 5c 57 69 66 65 5c 48 69 67 68 5c 6f 6e 63 65 5c 48 65 6c 70 42 65 74 77 65 65 6e 2e 70 64 62 } //01 00  c:\Wife\High\once\HelpBetween.pdb
		$a_01_10 = {63 56 6c 55 2e 70 64 62 } //01 00  cVlU.pdb
		$a_01_11 = {64 73 54 56 6a 6f 2e 70 64 62 } //01 00  dsTVjo.pdb
		$a_01_12 = {65 68 72 6a 72 68 77 2e 70 64 62 } //01 00  ehrjrhw.pdb
		$a_01_13 = {45 48 57 23 40 59 55 4a 45 25 4a 45 32 34 74 34 33 40 33 53 40 2e 70 64 62 } //01 00  EHW#@YUJE%JE24t43@3S@.pdb
		$a_01_14 = {45 57 48 23 40 31 77 48 4a 6e 45 52 62 52 57 2e 50 64 62 } //01 00  EWH#@1wHJnERbRW.Pdb
		$a_01_15 = {45 57 4a 45 52 6a 23 40 24 4a 74 65 6a 77 72 65 2e 70 64 62 } //01 00  EWJERj#@$Jtejwre.pdb
		$a_01_16 = {45 57 4a 74 43 6f 6d 70 6f 73 69 74 69 6f 6e 57 69 6e 77 72 65 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 51 23 23 23 23 2e 70 64 62 } //01 00  EWJtCompositionWinwreQQQQQQQQQQQQQQQQQQQQQQ####.pdb
		$a_01_17 = {68 65 45 48 52 6a 74 72 6b 6a 57 23 40 6a 65 74 2e 70 64 62 } //01 00  heEHRjtrkjW#@jet.pdb
		$a_01_18 = {68 57 45 48 57 23 40 48 4a 45 52 4b 4a 45 52 4a 45 52 5e 24 2e 50 64 62 } //01 00  hWEHW#@HJERKJERJER^$.Pdb
		$a_01_19 = {68 77 72 68 57 48 6e 65 68 57 52 23 40 68 57 47 57 45 5c 5c 5c 65 77 68 52 45 4c 42 77 65 5c 5c 2e 50 44 42 } //01 00  hwrhWHnehWR#@hWGWE\\\ewhRELBwe\\.PDB
		$a_01_20 = {69 6b 47 4c 75 4e 5a 6a 3d 58 37 41 2e 70 64 62 } //01 00  ikGLuNZj=X7A.pdb
		$a_01_21 = {4a 72 65 6b 4a 57 21 23 59 4a 65 74 6a 65 2e 70 64 62 } //01 00  JrekJW!#YJetje.pdb
		$a_01_22 = {4b 69 23 48 4a 54 45 4a 57 23 40 59 55 25 23 24 48 65 2e 70 64 62 } //01 00  Ki#HJTEJW#@YU%#$He.pdb
		$a_01_23 = {6d 68 58 72 4a 52 6d 4a 2e 70 64 62 } //01 00  mhXrJRmJ.pdb
		$a_01_24 = {4e 44 64 74 4e 23 6a 6f 4b 63 37 2e 70 64 62 } //01 00  NDdtN#joKc7.pdb
		$a_01_25 = {70 6a 5a 2a 36 64 42 52 2e 70 64 62 } //01 00  pjZ*6dBR.pdb
		$a_01_26 = {72 44 74 6b 74 2e 70 64 62 } //01 00  rDtkt.pdb
		$a_01_27 = {76 77 65 31 32 33 23 2e 50 44 42 } //01 00  vwe123#.PDB
		$a_01_28 = {77 65 68 6a 57 45 4a 48 77 6c 65 23 4c 3b 2e 70 64 62 } //01 00  wehjWEJHwle#L;.pdb
		$a_01_29 = {57 45 68 57 33 79 68 45 52 54 6a 51 29 45 28 52 48 29 28 2a 57 52 28 2e 70 64 62 } //01 00  WEhW3yhERTjQ)E(RH)(*WR(.pdb
		$a_01_30 = {77 47 65 74 45 78 74 57 45 4a 48 77 44 69 42 75 69 6c 64 43 6c 61 73 73 49 3b 2e 70 64 62 } //01 00  wGetExtWEJHwDiBuildClassI;.pdb
		$a_01_31 = {57 48 45 65 77 2e 70 64 62 } //00 00  WHEew.pdb
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_DE_2{
	meta:
		description = "Trojan:Win32/Emotet.DE,SIGNATURE_TYPE_PEHSTR,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 44 30 48 30 4c 30 50 30 54 30 58 30 } //01 00  0D0H0L0P0T0X0
		$a_01_1 = {40 00 40 00 23 00 40 00 47 00 57 00 52 00 42 00 57 00 65 00 40 00 40 00 } //01 00  @@#@GWRBWe@@
		$a_01_2 = {55 6e 72 65 61 6c 69 7a 65 4f 62 6a 65 63 74 2e 50 44 42 } //02 00  UnrealizeObject.PDB
		$a_01_3 = {41 67 61 69 6e 5c 66 6f 72 65 73 74 75 73 65 2e 70 64 62 } //02 00  Again\forestuse.pdb
		$a_01_4 = {59 72 37 37 7c 31 75 79 67 77 2e 2e 70 64 62 } //00 00  Yr77|1uygw..pdb
	condition:
		any of ($a_*)
 
}