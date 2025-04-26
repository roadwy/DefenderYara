
rule Ransom_Win32_Nemty_MMV_MTB{
	meta:
		description = "Ransom:Win32/Nemty.MMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 3a 58 66 89 45 ee 6a 5c 58 66 89 45 ?? 33 c0 66 89 45 ?? 8d 45 ec 83 c1 ?? 50 66 89 4d ?? ff 15 ?? ?? ?? ?? 6a 04 57 89 45 } //1
		$a_80_1 = {36 4e 45 50 48 49 4c 49 4d 2d 44 45 43 52 59 50 54 2e 74 78 74 } //6NEPHILIM-DECRYPT.txt  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}