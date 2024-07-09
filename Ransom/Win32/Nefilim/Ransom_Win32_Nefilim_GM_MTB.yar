
rule Ransom_Win32_Nefilim_GM_MTB{
	meta:
		description = "Ransom:Win32/Nefilim.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 1c 03 8b [0-10] 8a 14 01 8a 08 88 5d [0-15] 8a 1c 03 [0-64] 32 93 [0-30] 8a 1c 33 32 da [0-30] 32 d1 88 50 ?? 8a 0e 32 4d [0-10] 88 4e [0-25] 32 4d [0-10] 88 0f } //1
		$a_00_1 = {2f 63 20 57 6d 49 63 20 53 68 61 44 6f 77 63 6f 50 59 20 64 65 6c 45 74 65 } //1 /c WmIc ShaDowcoPY delEte
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}