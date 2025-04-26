
rule Trojan_Win32_Emotet_PC{
	meta:
		description = "Trojan:Win32/Emotet.PC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 64 75 39 37 48 61 33 36 6c 65 54 52 57 72 } //1 =du97Ha36leTRWr
		$a_01_1 = {78 39 6e 6a 6d 26 33 34 61 34 73 65 47 36 67 66 42 63 31 31 } //1 x9njm&34a4seG6gfBc11
		$a_01_2 = {52 43 72 70 31 74 65 5b 39 6c 65 54 52 } //1 RCrp1te[9leTR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}