
rule Ransom_MSIL_SerpenCrypt_B{
	meta:
		description = "Ransom:MSIL/SerpenCrypt.B,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 6f 00 6e 00 74 00 61 00 69 00 6e 00 73 00 20 00 53 00 46 00 58 00 20 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 73 00 } //01 00  contains SFX script commands
		$a_01_1 = {54 00 65 00 6d 00 70 00 4d 00 6f 00 64 00 65 00 } //01 00  TempMode
		$a_01_2 = {53 00 69 00 6c 00 65 00 6e 00 74 00 3d 00 31 00 } //01 00  Silent=1
		$a_01_3 = {4f 00 76 00 65 00 72 00 77 00 72 00 69 00 74 00 65 00 3d 00 32 00 } //01 00  Overwrite=2
		$a_01_4 = {53 00 65 00 74 00 75 00 70 00 3d 00 54 00 78 00 6f 00 65 00 6f 00 61 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  Setup=Txoeoaon.exe
		$a_01_5 = {48 00 68 00 72 00 72 00 78 00 6f 00 65 00 6f 00 61 00 6f 00 6e 00 2e 00 62 00 69 00 6e 00 } //01 00  Hhrrxoeoaon.bin
		$a_01_6 = {4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 73 } //01 00  Microsoft.VisualBasic.ApplicationServices
		$a_01_7 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //00 00  System.Reflection
	condition:
		any of ($a_*)
 
}