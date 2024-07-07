
rule TrojanSpy_Win32_Spynoon_STEL_MTB{
	meta:
		description = "TrojanSpy:Win32/Spynoon.STEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {65 77 69 75 65 67 70 } //1 ewiuegp
		$a_01_1 = {68 6e 65 73 65 71 6e 70 75 } //1 hneseqnpu
		$a_01_2 = {6b 73 6f 6e 65 72 76 78 64 } //1 ksonervxd
		$a_01_3 = {6d 71 76 69 62 7a } //1 mqvibz
		$a_01_4 = {70 77 79 69 6c 6f 62 64 } //1 pwyilobd
		$a_01_5 = {75 72 65 74 73 75 6d 6f 6a 79 72 } //1 uretsumojyr
		$a_01_6 = {76 63 72 73 6c 71 } //1 vcrslq
		$a_01_7 = {76 64 61 65 70 64 78 6d 6a 74 68 } //1 vdaepdxmjth
		$a_01_8 = {77 74 66 65 6a } //1 wtfej
		$a_01_9 = {78 65 6a 6e 79 69 } //1 xejnyi
		$a_01_10 = {2e 72 64 61 74 61 24 7a 7a 7a 64 62 67 } //1 .rdata$zzzdbg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}