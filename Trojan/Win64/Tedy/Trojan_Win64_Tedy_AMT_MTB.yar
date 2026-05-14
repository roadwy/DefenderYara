
rule Trojan_Win64_Tedy_AMT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 36 32 2e 36 30 2e 32 32 36 2e 32 34 38 3a 35 35 35 33 2f [0-0f] 2e 65 78 65 } //5
		$a_80_1 = {64 6f 64 70 70 2e 65 78 65 } //dodpp.exe  1
		$a_80_2 = {41 64 64 69 6e 67 20 64 69 72 65 63 74 6f 72 69 65 73 20 74 6f 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 65 78 63 6c 75 73 69 6f 6e 20 6c 69 73 74 } //Adding directories to Windows Defender exclusion list  1
		$a_80_3 = {53 6b 69 70 70 69 6e 67 20 65 78 63 6c 75 73 69 6f 6e 20 66 6f 72 20 72 61 6e 64 6f 6d 20 66 6f 6c 64 65 72 } //Skipping exclusion for random folder  1
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}