
rule Ransom_Win32_FileCoder_GPAB_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.GPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin Delete Shadows /all /quiet
		$a_01_1 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 wmic shadowcopy delete
		$a_01_2 = {5c 47 6c 69 74 63 68 42 79 74 65 2e 62 6d } //4 \GlitchByte.bm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*4) >=6
 
}