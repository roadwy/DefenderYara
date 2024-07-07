
rule Virus_WinNT_Cutwail_gen_B{
	meta:
		description = "Virus:WinNT/Cutwail.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 da 84 ae 28 68 28 5f c3 d0 8b 45 fc 50 e8 90 01 04 a3 90 01 04 68 e8 d8 02 9a 68 5d 33 78 df 8b 4d fc 51 e8 90 01 04 a3 90 01 04 68 68 3c 59 02 68 78 33 78 df 8b 55 fc 90 00 } //1
		$a_00_1 = {c1 e9 02 85 c9 74 0b 31 06 83 c6 04 c1 c0 03 49 eb f1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}