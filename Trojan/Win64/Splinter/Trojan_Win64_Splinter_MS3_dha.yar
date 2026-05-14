
rule Trojan_Win64_Splinter_MS3_dha{
	meta:
		description = "Trojan:Win64/Splinter.MS3!dha,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 69 74 69 61 6c 69 7a 65 20 69 6d 70 6c 61 6e 74 } //10 Failed to initialize implant
		$a_01_1 = {69 6d 70 6c 61 6e 74 5f 65 78 65 2e 70 64 62 } //10 implant_exe.pdb
		$a_01_2 = {6c 6f 61 64 65 72 2e 64 6c 6c } //5 loader.dll
		$a_01_3 = {73 68 65 6c 6c 63 6f 64 65 } //5 shellcode
		$a_01_4 = {55 55 49 44 20 70 61 72 73 69 6e 67 20 66 61 69 6c 65 64 3a } //5 UUID parsing failed:
		$a_01_5 = {43 6f 6e 66 69 67 20 77 69 74 68 } //5 Config with
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=25
 
}