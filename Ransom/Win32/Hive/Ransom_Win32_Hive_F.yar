
rule Ransom_Win32_Hive_F{
	meta:
		description = "Ransom:Win32/Hive.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 6b 65 79 } //1 .key
		$a_02_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 ?? 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //1
		$a_03_2 = {65 78 65 4e 55 4c 63 6f 75 6c 64 6e 27 74 20 67 65 6e 65 72 61 74 65 20 72 61 6e 64 6f 6d 20 62 ?? 74 65 73 3a 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}