
rule Worm_Win32_Shreptaz_A{
	meta:
		description = "Worm:Win32/Shreptaz.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 ec 44 04 00 00 c6 45 d8 63 c6 45 d9 72 c6 45 da 61 c6 45 db 73 c6 45 dc 68 c6 45 dd 72 c6 45 de 65 } //01 00 
		$a_01_1 = {61 74 74 72 69 62 20 2b 72 20 2b 73 20 2b 68 20 63 72 61 73 68 72 65 70 6f 72 74 2e 65 78 65 } //01 00  attrib +r +s +h crashreport.exe
		$a_01_2 = {62 69 74 2e 6c 79 2f 34 4e 46 39 4b 4a } //01 00  bit.ly/4NF9KJ
		$a_01_3 = {74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 6e 32 61 6e 76 73 } //00 00  tinyurl.com/n2anvs
	condition:
		any of ($a_*)
 
}