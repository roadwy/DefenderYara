
rule Trojan_Win64_Shelm_F_MTB{
	meta:
		description = "Trojan:Win64/Shelm.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 63 6f 64 65 20 61 74 20 25 70 } //02 00  Shell code at %p
		$a_01_1 = {4d 79 20 73 68 65 6c 6c 63 6f 64 65 20 70 6f 69 6e 74 65 72 20 25 70 } //02 00  My shellcode pointer %p
		$a_01_2 = {54 68 72 65 61 64 20 63 72 65 61 74 65 64 20 61 74 } //02 00  Thread created at
		$a_01_3 = {64 6c 6c 5f 70 61 74 68 20 5b 70 72 6f 63 65 73 73 5f 6e 61 6d 65 5d } //00 00  dll_path [process_name]
	condition:
		any of ($a_*)
 
}