
rule Ransom_Win32_Lockbit_AC_MTB{
	meta:
		description = "Ransom:Win32/Lockbit.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 7f 8b cb 5e 8a 84 ?? 69 ff ff ff 0f b6 c0 83 e8 ?? 6b c0 ?? 99 f7 fe 8d 04 16 99 f7 fe 88 94 0d 69 ff ff ff 41 83 f9 16 90 13 8a 84 ?? 69 ff ff ff } //1
		$a_03_1 = {6a 7f 8b f3 5f 8a 84 ?? 69 ff ff ff 0f b6 c0 6a ?? 59 2b c8 6b c1 ?? 99 f7 ff 8d 04 17 99 f7 ff 88 94 ?? 69 ff ff ff 46 83 fe 16 90 13 8a 84 ?? 69 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}