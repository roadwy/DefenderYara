
rule Trojan_Win64_Pinchloader_B_dha{
	meta:
		description = "Trojan:Win64/Pinchloader.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 61 69 6c 65 64 20 74 6f 20 61 6c 6c 6f 63 61 74 65 20 6d 65 6d 6f 72 79 20 66 6f 72 20 73 68 65 6c 6c 63 6f 64 65 } //1 Failed to allocate memory for shellcode
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 63 68 61 6e 67 65 20 6d 65 6d 6f 72 79 20 70 72 6f 74 65 63 74 69 6f 6e } //1 Failed to change memory protection
		$a_01_2 = {2e 64 6c 6c 00 6f 6b 67 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}