
rule Ransom_MSIL_Jigsaw_AJY_MSR{
	meta:
		description = "Ransom:MSIL/Jigsaw.AJY!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 69 74 63 6f 69 6e 42 6c 61 63 6b 6d 61 69 6c 65 72 5c 42 69 74 63 6f 69 6e 42 6c 61 63 6b 6d 61 69 6c 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 42 69 74 63 6f 69 6e 42 6c 61 63 6b 6d 61 69 6c 65 72 2e 70 64 62 } //01 00  BitcoinBlackmailer\BitcoinBlackmailer\bin\Release\BitcoinBlackmailer.pdb
		$a_01_1 = {42 69 74 63 6f 69 6e 42 6c 61 63 6b 6d 61 69 6c 65 72 2e 65 78 65 } //01 00  BitcoinBlackmailer.exe
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //01 00  CreateEncryptor
		$a_01_3 = {51 00 6d 00 6c 00 30 00 59 00 32 00 39 00 70 00 62 00 6b 00 4a 00 73 00 59 00 57 00 4e 00 72 00 62 00 57 00 46 00 70 00 62 00 47 00 56 00 79 00 4a 00 51 00 3d 00 3d 00 } //00 00  Qml0Y29pbkJsYWNrbWFpbGVyJQ==
	condition:
		any of ($a_*)
 
}