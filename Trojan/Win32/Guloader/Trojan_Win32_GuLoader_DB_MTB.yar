
rule Trojan_Win32_GuLoader_DB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6e 61 6e 73 6c 6f 76 66 6f 72 73 6c 61 67 65 74 73 5c 45 72 68 6f 6c 64 65 6c 69 67 65 } //01 00  Finanslovforslagets\Erholdelige
		$a_01_1 = {53 6b 69 62 73 70 72 6f 76 69 61 6e 74 65 72 69 6e 67 73 68 61 6e 64 6c 65 72 65 6e 73 5c 4b 6c 61 70 73 74 6f 6c 5c 53 76 65 6e 73 6b 65 6b 6f 6e 67 65 72 5c 41 61 73 6d 75 6e 64 2e 69 6e 69 } //01 00  Skibsprovianteringshandlerens\Klapstol\Svenskekonger\Aasmund.ini
		$a_01_2 = {50 6c 6f 76 65 72 73 5c 42 65 72 69 67 6e 69 6e 67 65 72 2e 49 61 72 } //01 00  Plovers\Berigninger.Iar
		$a_01_3 = {44 69 73 6b 6a 6f 63 6b 65 79 5c 43 6c 61 76 61 72 69 61 63 65 61 65 5c 53 70 72 75 63 69 65 73 74 5c 49 6e 76 65 73 74 65 72 69 6e 67 73 70 6f 6c 69 74 69 6b 6b 65 6e 2e 45 61 74 } //01 00  Diskjockey\Clavariaceae\Spruciest\Investeringspolitikken.Eat
		$a_01_4 = {46 6c 75 67 74 73 69 6b 72 65 73 74 65 5c 53 6b 61 62 69 6f 73 65 72 6e 65 73 5c 6b 6e 79 73 74 65 74 5c 53 66 72 65 72 73 2e 48 61 72 } //00 00  Flugtsikreste\Skabiosernes\knystet\Sfrers.Har
	condition:
		any of ($a_*)
 
}