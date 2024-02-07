
rule TrojanSpy_Win32_Spynoon_STEL_MTB{
	meta:
		description = "TrojanSpy:Win32/Spynoon.STEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 77 69 75 65 67 70 } //01 00  ewiuegp
		$a_01_1 = {68 6e 65 73 65 71 6e 70 75 } //01 00  hneseqnpu
		$a_01_2 = {6b 73 6f 6e 65 72 76 78 64 } //01 00  ksonervxd
		$a_01_3 = {6d 71 76 69 62 7a } //01 00  mqvibz
		$a_01_4 = {70 77 79 69 6c 6f 62 64 } //01 00  pwyilobd
		$a_01_5 = {75 72 65 74 73 75 6d 6f 6a 79 72 } //01 00  uretsumojyr
		$a_01_6 = {76 63 72 73 6c 71 } //01 00  vcrslq
		$a_01_7 = {76 64 61 65 70 64 78 6d 6a 74 68 } //01 00  vdaepdxmjth
		$a_01_8 = {77 74 66 65 6a } //01 00  wtfej
		$a_01_9 = {78 65 6a 6e 79 69 } //01 00  xejnyi
		$a_01_10 = {2e 72 64 61 74 61 24 7a 7a 7a 64 62 67 } //00 00  .rdata$zzzdbg
	condition:
		any of ($a_*)
 
}