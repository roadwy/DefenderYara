
rule Virus_Win32_Almanahe_gen_A{
	meta:
		description = "Virus:Win32/Almanahe.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {5b b9 cd 04 00 00 80 ?? 19 ?? e2 fa eb 06 e8 ed ff ff ff } //1
		$a_00_1 = {54 68 69 73 20 66 6f 6c 64 65 72 20 68 61 73 20 62 65 65 6e 20 63 72 65 61 74 65 64 20 62 79 20 53 6d 61 72 74 43 4f 50 20 41 6e 74 69 2d 56 69 72 75 73 20 74 6f 20 69 6d 6d 75 6e 69 7a 65 } //-1 This folder has been created by SmartCOP Anti-Virus to immunize
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*-1) >=1
 
}