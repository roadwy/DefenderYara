
rule TrojanDownloader_Win32_Banload_ATB{
	meta:
		description = "TrojanDownloader:Win32/Banload.ATB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_80_0 = {6e 6f 64 31 30 2f 6d 61 6e 61 34 2e 70 64 66 00 } //nod10/mana4.pdf  1
		$a_80_1 = {6e 6f 64 37 30 2f 6a 75 6c 69 61 31 30 2e 68 6c 70 00 } //nod70/julia10.hlp  1
		$a_80_2 = {68 74 74 70 3a 2f 2f 63 70 72 6f 31 37 37 33 38 2e 70 75 62 6c 69 63 63 6c 6f 75 64 2e 63 6f 6d 2e 62 72 2f } //http://cpro17738.publiccloud.com.br/  2
		$a_01_3 = {00 43 50 6c 41 70 70 6c 65 74 00 } //10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_01_3  & 1)*10) >=13
 
}