
rule Ransom_Win32_Wannaren_A{
	meta:
		description = "Ransom:Win32/Wannaren.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 57 61 6e 6e 61 52 65 6e } //2 .WannaRen
		$a_01_1 = {43 72 79 70 74 47 65 74 4b 65 79 50 61 72 61 6d 00 44 65 6c 65 74 65 46 69 6c 65 41 00 50 61 74 68 46 69 6e 64 46 69 6c 65 } //1
		$a_03_2 = {41 ff ff ff 81 ?? 3f ff ff ff c1 ?? 0a 81 ?? ff 01 00 00 81 ?? ff 01 00 00 81 ?? ff 7f 00 00 } //1
		$a_03_3 = {75 50 80 7c ?? ?? 64 75 49 80 7c ?? ?? 6f 75 42 80 7c ?? ?? 62 75 3b 80 7c ?? ?? 65 75 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}