
rule Trojan_Win64_Tedy_ABMT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ABMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 6f 77 65 72 63 66 67 20 2f 68 69 62 65 72 6e 61 74 65 20 6f 66 66 } //cmd.exe /C powercfg /hibernate off  1
		$a_80_1 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 6f 77 65 72 63 66 67 20 2f 63 68 61 6e 67 65 20 6d 6f 6e 69 74 6f 72 2d 74 69 6d 65 6f 75 74 2d 61 63 20 30 } //cmd.exe /C powercfg /change monitor-timeout-ac 0  1
		$a_02_2 = {3a 2f 2f 63 79 76 6f 72 61 2e 6e 65 74 [0-0a] 2e 74 78 74 } //1
		$a_02_3 = {3a 2f 2f 65 63 68 6f 6c 69 6e 6b 72 2e 63 6f 6d [0-0a] 2e 74 78 74 } //1
		$a_80_4 = {4c 6f 61 64 65 72 2e 70 64 62 } //Loader.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}