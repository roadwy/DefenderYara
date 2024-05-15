
rule Ransom_Win32_RaLock_YAA_MTB{
	meta:
		description = "Ransom:Win32/RaLock.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 41 20 57 6f 72 6c 64 } //01 00  RA World
		$a_01_1 = {48 65 6c 6c 6f 21 20 54 75 62 65 78 21 } //01 00  Hello! Tubex!
		$a_01_2 = {73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //01 00  stolen and encrypted
		$a_01_3 = {2e 6f 6e 69 6f 6e } //01 00  .onion
		$a_01_4 = {72 65 6c 65 61 73 65 20 74 68 65 20 64 61 74 61 } //01 00  release the data
		$a_01_5 = {72 61 6e 73 6f 6d } //00 00  ransom
	condition:
		any of ($a_*)
 
}