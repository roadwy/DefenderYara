
rule Ransom_MSIL_Kraken_D{
	meta:
		description = "Ransom:MSIL/Kraken.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 72 79 70 74 6f 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 55 41 43 5c 55 41 43 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 55 41 43 2e 70 64 62 } //01 00  Krypton\source\repos\UAC\UAC\obj\Release\UAC.pdb
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6d 00 73 00 63 00 66 00 69 00 6c 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //01 00  SOFTWARE\Classes\mscfile\shell\open\command
		$a_01_2 = {4b 72 61 6b 65 6e 2e 65 78 65 } //01 00  Kraken.exe
		$a_01_3 = {4b 52 41 4b 45 4e 5f 55 4e 49 51 55 45 5f 4b 45 59 } //01 00  KRAKEN_UNIQUE_KEY
		$a_01_4 = {4b 00 72 00 61 00 6b 00 65 00 6e 00 20 00 43 00 72 00 79 00 70 00 74 00 6f 00 72 00 } //01 00  Kraken Cryptor
		$a_01_5 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 } //00 00  vssadmin delete shadows /All
	condition:
		any of ($a_*)
 
}