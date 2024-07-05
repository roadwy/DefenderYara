
rule Ransom_Win32_Fog_D{
	meta:
		description = "Ransom:Win32/Fog.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 65 20 6d 61 78 69 6d 75 6d 20 6e 75 6d 62 65 72 20 6f 66 20 70 72 6f 63 65 73 73 65 73 20 68 61 73 20 62 65 65 6e 20 72 65 61 63 68 65 64 21 } //01 00  he maximum number of processes has been reached!
		$a_01_1 = {5b 2d 5d 20 43 72 79 70 74 45 6e 63 72 79 70 74 28 29 20 65 72 72 6f 72 2c 20 63 6f 64 65 3a 20 25 64 } //01 00  [-] CryptEncrypt() error, code: %d
		$a_01_2 = {5b 21 5d 20 41 6c 6c 20 74 61 73 6b 20 66 69 6e 69 73 68 65 64 2c 20 6c 6f 63 6b 65 72 20 65 78 69 74 69 6e 67 2e } //00 00  [!] All task finished, locker exiting.
	condition:
		any of ($a_*)
 
}