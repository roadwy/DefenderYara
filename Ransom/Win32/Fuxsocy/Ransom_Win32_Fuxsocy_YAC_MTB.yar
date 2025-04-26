
rule Ransom_Win32_Fuxsocy_YAC_MTB{
	meta:
		description = "Ransom:Win32/Fuxsocy.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 03 69 c0 ?? ?? ?? ?? c1 c0 0f 69 c0 ?? ?? ?? ?? 33 e8 c1 c5 0d 6b ed 05 83 c3 04 81 ed ?? ?? ?? ?? 3b da 72 da } //10
		$a_01_1 = {6d 48 05 6e 30 8b 19 ed bc 70 26 18 37 7a 3e 1c f2 5d 53 60 77 30 98 33 e3 ce 1c 7f 4d 54 b4 3f 8e a0 3c ba 31 df 1e 0b d4 5f } //6
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*6) >=16
 
}