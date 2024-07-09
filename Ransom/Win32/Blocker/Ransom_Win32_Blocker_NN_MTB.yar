
rule Ransom_Win32_Blocker_NN_MTB{
	meta:
		description = "Ransom:Win32/Blocker.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 14 37 03 c2 8b 55 ?? 81 c2 ?? ?? 00 00 8b ca 33 d2 f7 f1 8a 04 17 88 45 ?? 8d 45 ?? 8b 55 ?? 8b 4d ?? 8a 54 0a ?? 8a 4d ?? 32 d1 e8 } //1
		$a_02_1 = {6a 00 6a 00 8b c3 2d b7 a0 0b 00 50 6a 00 8b c3 2d b9 a0 0b 00 50 81 c3 46 5f f4 7f 53 8b 45 ?? e8 c4 60 fb ff 50 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}