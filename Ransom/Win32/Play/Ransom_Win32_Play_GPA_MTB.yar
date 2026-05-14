
rule Ransom_Win32_Play_GPA_MTB{
	meta:
		description = "Ransom:Win32/Play.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f1 0f be 54 15 ?? 8b 45 ?? 03 45 ?? 0f be 08 33 ca 8b 55 90 1b 01 03 55 90 1b 02 88 0a eb c9 6a 40 68 00 30 00 00 8b 45 ?? 50 6a 00 ff 55 } //4
		$a_01_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 } //3 LoadLibrary
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}