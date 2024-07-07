
rule Ransom_Win32_BlackCat_F{
	meta:
		description = "Ransom:Win32/BlackCat.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 85 18 ff ff ff 74 65 20 6b c7 85 44 ff ff ff 32 2d 62 79 c7 85 68 ff ff ff 6e 64 20 33 90 01 01 85 48 ff ff ff 65 78 70 61 90 00 } //1
		$a_01_1 = {3d 43 01 00 00 7d } //-1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*-1) >=1
 
}