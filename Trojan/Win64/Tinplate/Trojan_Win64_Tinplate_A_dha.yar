
rule Trojan_Win64_Tinplate_A_dha{
	meta:
		description = "Trojan:Win64/Tinplate.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6f 69 6e 67 4f 6e 4e 65 74 20 6f 70 65 72 61 74 69 6f 6e } //1 doingOnNet operation
		$a_01_1 = {64 6f 69 6e 67 4f 6e 44 69 73 6b 20 6f 70 65 72 61 74 69 6f 6e } //1 doingOnDisk operation
		$a_01_2 = {64 6f 69 6e 67 4f 6e 4e 65 74 2e 74 78 74 } //1 doingOnNet.txt
		$a_01_3 = {64 6f 69 6e 67 4f 6e 44 69 73 6b 2e 74 78 74 } //1 doingOnDisk.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}