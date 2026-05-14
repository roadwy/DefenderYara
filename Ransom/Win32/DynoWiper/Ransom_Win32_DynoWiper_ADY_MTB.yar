
rule Ransom_Win32_DynoWiper_ADY_MTB{
	meta:
		description = "Ransom:Win32/DynoWiper.ADY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {52 ff d7 f6 c3 01 74 27 8d 4c 24 10 8d 46 61 51 66 89 44 24 14 ff 15 ?? ?? ?? ?? 83 f8 03 75 0f 8d 54 24 10 6a 05 52 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}