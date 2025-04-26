
rule Trojan_Win64_Tedy_GB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 10 48 8b 45 f8 48 01 d0 0f b6 00 48 8b 4d 10 48 8b 55 f8 48 01 ca 32 45 20 88 02 48 83 45 f8 01 48 8b 45 f8 48 3b 45 18 72 d3 } //1
		$a_01_1 = {72 75 6e 5f 65 78 65 5f 66 72 6f 6d 5f 6d 65 6d 6f 72 79 } //1 run_exe_from_memory
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}