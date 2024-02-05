
rule Ransom_Win64_Lockbit_AC_MTB{
	meta:
		description = "Ransom:Win64/Lockbit.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 88 4c 3c 41 48 ff c7 48 83 ff 16 72 } //01 00 
		$a_01_1 = {f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 42 88 4c 05 b8 49 ff c0 49 83 f8 0d 72 } //00 00 
	condition:
		any of ($a_*)
 
}