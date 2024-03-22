
rule Ransom_Win32_FileCoder_SGA_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.SGA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //01 00  All your important files are encrypted!
		$a_01_1 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 2e } //01 00  Do not rename encrypted files.
		$a_01_2 = {52 00 65 00 73 00 74 00 6f 00 72 00 65 00 2d 00 4d 00 79 00 2d 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //00 00  Restore-My-Files.txt
	condition:
		any of ($a_*)
 
}