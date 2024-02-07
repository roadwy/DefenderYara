
rule Trojan_Win64_Emotet_BA_MSR{
	meta:
		description = "Trojan:Win64/Emotet.BA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {49 70 6f 73 69 6f 67 73 65 6f 67 6a 73 65 69 6f 6a 67 65 69 } //02 00  Iposiogseogjseiojgei
		$a_01_1 = {50 61 72 74 69 74 69 6f 6e 57 69 7a 61 72 64 45 6e 74 72 79 50 6f 69 6e 74 } //02 00  PartitionWizardEntryPoint
		$a_01_2 = {6f 70 69 66 6f 69 70 77 34 39 30 66 67 73 6a 67 69 73 65 69 72 68 6a } //02 00  opifoipw490fgsjgiseirhj
		$a_01_3 = {6b 6d 6e 45 47 6c 44 56 43 63 63 4d 6b 78 42 69 43 4e 75 66 76 71 4d 4a 4b 78 } //02 00  kmnEGlDVCccMkxBiCNufvqMJKx
		$a_01_4 = {6d 4a 69 51 6c 49 76 64 4d 69 4c 4e 45 51 73 67 64 49 4b 55 64 66 52 6f 69 } //02 00  mJiQlIvdMiLNEQsgdIKUdfRoi
		$a_01_5 = {49 4e 43 63 59 78 54 53 47 72 54 4c 58 72 48 47 46 79 75 56 45 4f } //02 00  INCcYxTSGrTLXrHGFyuVEO
		$a_01_6 = {6d 54 75 6f 72 43 61 4f 77 65 66 43 65 75 4a 5a 6d 6c 6f 6d 52 6b 6a 4e 4e 47 43 56 6c } //02 00  mTuorCaOwefCeuJZmlomRkjNNGCVl
		$a_01_7 = {44 69 6e 78 50 63 53 62 53 59 6b 75 72 6a 6c 45 4b 4a 62 6e 67 } //00 00  DinxPcSbSYkurjlEKJbng
	condition:
		any of ($a_*)
 
}