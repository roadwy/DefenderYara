
rule Ransom_Win32_Conti_ZZ_MTB{
	meta:
		description = "Ransom:Win32/Conti.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 f8 0f b6 9f ?? ?? ?? 00 0f b6 04 31 03 da 03 c3 99 bb ?? ?? ?? ?? f7 fb 8a 04 31 83 c7 01 0f b6 d2 8a 1c 0a 88 1c 31 88 04 0a 8b c7 25 ?? ?? ?? ?? 79 05 48 83 c8 c0 40 83 c6 01 81 fe 90 1b 01 7c bb } //1
		$a_03_1 = {8d 46 01 99 be ?? ?? ?? ?? f7 fe bb 90 1b 00 83 c5 01 0f b6 f2 0f b6 04 0e 03 c7 88 54 24 12 99 bf 90 1b 00 f7 ff 8a 04 0e 0f b6 fa 88 54 24 13 0f b6 14 0f 88 14 0e 88 04 0f 0f b6 14 0f 0f b6 04 0e 03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 30 55 ff 83 6c 24 14 01 75 a6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}