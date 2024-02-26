
rule Trojan_Win64_Shelm_K_MTB{
	meta:
		description = "Trojan:Win64/Shelm.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 c9 48 83 f8 90 01 01 48 0f 46 c8 42 0f b6 04 90 01 01 41 30 04 18 48 8d 41 90 00 } //02 00 
		$a_01_1 = {44 65 63 72 79 70 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 } //00 00  Decrypting shellcode
	condition:
		any of ($a_*)
 
}