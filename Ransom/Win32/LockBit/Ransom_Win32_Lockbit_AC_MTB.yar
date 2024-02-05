
rule Ransom_Win32_Lockbit_AC_MTB{
	meta:
		description = "Ransom:Win32/Lockbit.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 7f 8b cb 5e 8a 84 90 01 01 69 ff ff ff 0f b6 c0 83 e8 90 01 01 6b c0 90 01 01 99 f7 fe 8d 04 16 99 f7 fe 88 94 0d 69 ff ff ff 41 83 f9 16 90 13 8a 84 90 01 01 69 ff ff ff 90 00 } //01 00 
		$a_03_1 = {6a 7f 8b f3 5f 8a 84 90 01 01 69 ff ff ff 0f b6 c0 6a 90 01 01 59 2b c8 6b c1 90 01 01 99 f7 ff 8d 04 17 99 f7 ff 88 94 90 01 01 69 ff ff ff 46 83 fe 16 90 13 8a 84 90 01 01 69 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}