
rule Backdoor_Win32_Turla_X_dha{
	meta:
		description = "Backdoor:Win32/Turla.X!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {f7 d1 83 e1 08 81 e3 f7 1f 00 00 33 d9 8b cb c1 f9 0a d1 f8 83 e1 07 } //1
		$a_01_1 = {f7 d1 41 81 e4 f7 1f 00 00 83 e1 08 44 33 e1 41 8b cc c1 f9 0a 83 e1 07 } //1
		$a_01_2 = {4b 00 65 00 72 00 6e 00 65 00 6c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 3a 00 3a 00 43 00 6f 00 70 00 79 00 44 00 6c 00 6c 00 46 00 72 00 6f 00 6d 00 42 00 75 00 66 00 66 00 65 00 72 00 } //1 KernelInjector::CopyDllFromBuffer
		$a_01_3 = {4b 00 65 00 72 00 6e 00 65 00 6c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 3a 00 3a 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 } //1 KernelInjector::KernelInjector
		$a_01_4 = {7b 00 35 00 33 00 31 00 35 00 31 00 31 00 46 00 41 00 2d 00 31 00 39 00 30 00 44 00 2d 00 35 00 44 00 38 00 35 00 2d 00 38 00 41 00 34 00 41 00 2d 00 32 00 37 00 39 00 46 00 32 00 46 00 35 00 39 00 32 00 43 00 43 00 37 00 7d 00 } //1 {531511FA-190D-5D85-8A4A-279F2F592CC7}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}