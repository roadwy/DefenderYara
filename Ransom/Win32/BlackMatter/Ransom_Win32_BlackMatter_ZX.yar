
rule Ransom_Win32_BlackMatter_ZX{
	meta:
		description = "Ransom:Win32/BlackMatter.ZX,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {b8 41 42 43 44 ab b8 45 46 47 48 ab b8 49 4a 4b 4c ab b8 4d 4e 4f 50 ab b8 51 52 53 54 ab b8 55 56 57 58 ab b8 59 5a 61 62 ab b8 63 64 65 66 ab b8 67 68 69 6a ab b8 6b 6c 6d 6e ab b8 6f 70 71 72 ab b8 73 74 75 76 ab b8 77 78 79 7a ab b8 30 31 32 33 ab b8 34 35 36 37 ab b8 38 39 2b 2f ab } //100
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*100) >=101
 
}