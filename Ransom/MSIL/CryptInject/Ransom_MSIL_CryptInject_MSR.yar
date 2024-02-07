
rule Ransom_MSIL_CryptInject_MSR{
	meta:
		description = "Ransom:MSIL/CryptInject!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 64 00 61 00 74 00 61 00 20 00 69 00 73 00 20 00 6e 00 6f 00 77 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2c 00 20 00 70 00 61 00 79 00 20 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 21 00 } //01 00  All your data is now encrypted, pay ransom!
		$a_00_1 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 77 00 61 00 72 00 6e 00 69 00 6e 00 67 00 } //01 00  Encryption warning
		$a_01_2 = {52 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //01 00  Ransomware.exe
		$a_01_3 = {44 65 62 75 67 5c 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //00 00  Debug\Ransomware.pdb
	condition:
		any of ($a_*)
 
}