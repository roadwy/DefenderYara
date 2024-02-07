
rule Ransom_Win32_VenusCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/VenusCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 76 65 6e 75 73 } //01 00  .venus
		$a_01_1 = {52 45 41 44 4d 45 2e 74 78 74 } //01 00  README.txt
		$a_01_2 = {68 65 6c 70 32 30 32 31 6d 65 40 61 6f 6c 2e 63 6f 6d } //01 00  help2021me@aol.com
		$a_01_3 = {66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //00 00  files has been encrypted
	condition:
		any of ($a_*)
 
}