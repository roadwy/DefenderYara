
rule Ransom_Win32_Crypmod_MAK_MTB{
	meta:
		description = "Ransom:Win32/Crypmod.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c6 b9 0a 00 00 00 99 f7 f9 80 c2 90 02 01 0f b6 c3 88 14 07 b9 0a 00 00 00 8b c6 99 f7 f9 89 c6 4b 85 f6 75 dc 90 00 } //1
		$a_80_1 = {52 65 61 64 4d 65 2e 74 78 74 } //ReadMe.txt  1
		$a_80_2 = {52 65 63 6f 76 65 72 79 2e 62 6d 70 } //Recovery.bmp  1
		$a_80_3 = {24 52 45 43 59 43 4c 45 2e 42 49 4e } //$RECYCLE.BIN  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}