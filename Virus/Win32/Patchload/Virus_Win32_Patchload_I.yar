
rule Virus_Win32_Patchload_I{
	meta:
		description = "Virus:Win32/Patchload.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 8b 50 08 8b 7c 02 08 3b fa 0f 87 ?? ?? ?? ?? 81 ff 38 01 00 00 0f 82 ?? ?? ?? ?? 68 34 9d 41 00 e8 } //1
		$a_01_1 = {6a 02 68 c8 9d 41 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}