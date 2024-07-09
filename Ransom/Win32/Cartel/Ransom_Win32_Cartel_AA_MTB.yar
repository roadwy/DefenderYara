
rule Ransom_Win32_Cartel_AA_MTB{
	meta:
		description = "Ransom:Win32/Cartel.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 01 0f b7 45 ?? 8b 4d ?? 0f b6 04 01 03 d0 0f b6 4d ?? 03 d1 81 e2 ff 00 00 00 88 55 ?? 0f b7 55 ?? 8b 45 ?? 8a 0c 10 88 4d ?? 0f b6 55 ?? 0f b7 45 f8 8b 4d ?? 8b 75 ?? 8a 14 16 88 14 01 0f b6 45 } //1
		$a_01_1 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //1 /c vssadmin.exe Delete Shadows /All /Quiet
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}