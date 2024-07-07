
rule Ransom_Win32_Conti_FF_MTB{
	meta:
		description = "Ransom:Win32/Conti.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 06 8d 76 01 0f b6 c0 83 e8 67 6b c0 25 99 f7 fb 8d 42 7f 99 f7 fb 88 56 ff 83 ef } //30
		$a_01_1 = {8a 07 8d 7f 01 0f b6 c8 83 e9 31 8d 04 cd 00 00 00 00 2b c1 c1 e0 02 99 f7 fe 8d 42 7f 99 f7 fe 88 57 ff 83 e8 } //30
		$a_01_2 = {8a 07 8d 7f 01 0f b6 c0 b9 1a 00 00 00 2b c8 8b c1 c1 e0 05 2b c1 03 c0 99 f7 fe 8d 42 7e 99 f7 fe 88 57 ff 83 } //30
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*30+(#a_01_2  & 1)*30) >=30
 
}