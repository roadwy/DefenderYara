
rule Virus_WinNT_Cutwail_gen_A{
	meta:
		description = "Virus:WinNT/Cutwail.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {b9 76 01 00 00 0f 32 66 25 00 f0 81 78 4e 54 68 69 73 74 03 48 eb f0 } //1
		$a_02_1 = {55 8b ec 51 e8 ?? ?? ?? ?? 89 45 fc 68 da 84 ae 28 68 28 5f c3 d0 8b 45 fc 50 e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}