
rule Trojan_Win32_Guloader_ASC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 72 62 69 64 69 73 65 73 5c 45 6e 72 69 76 65 5c 54 77 61 64 64 6c 69 65 72 5c 6d 69 6c 69 65 75 67 69 66 74 65 73 2e 69 6e 69 } //2 morbidises\Enrive\Twaddlier\milieugiftes.ini
		$a_01_1 = {54 6f 6e 73 69 6c 6c 61 72 5c 4d 61 72 67 69 6e 69 66 6f 72 6d 5c 4d 75 73 6b 6d 65 6c 6f 6e } //1 Tonsillar\Marginiform\Muskmelon
		$a_01_2 = {54 79 6d 70 61 6e 69 66 6f 72 6d 25 5c 4b 61 6c 66 61 6b 74 6f 72 5c 53 61 6d 66 75 6e 64 73 62 65 76 69 64 73 74 5c 46 69 6c 6b 61 6c 64 65 74 73 5c 42 72 65 76 62 72 65 72 65 6e 73 2e 42 69 6e } //1 Tympaniform%\Kalfaktor\Samfundsbevidst\Filkaldets\Brevbrerens.Bin
		$a_01_3 = {44 79 73 69 64 72 6f 73 69 73 5c 49 6c 6d 61 72 63 68 65 6e 73 5c 47 72 61 65 64 65 66 61 65 72 64 69 67 5c 42 75 6d 6d 61 6c 6f } //1 Dysidrosis\Ilmarchens\Graedefaerdig\Bummalo
		$a_01_4 = {44 75 70 6c 69 6b 61 74 65 74 73 5c 69 6d 70 65 72 61 74 69 76 65 72 5c 53 61 6d 66 75 6e 64 73 6e 79 74 74 65 68 65 6e 73 79 6e 73 5c 4e 65 75 72 6f 6c 79 6d 70 68 2e 69 6e 69 } //1 Duplikatets\imperativer\Samfundsnyttehensyns\Neurolymph.ini
		$a_01_5 = {4c 69 6e 6a 65 76 6f 67 74 65 72 73 5c 74 65 6c 65 66 6f 6e 62 6f 6b 73 65 6e 65 2e 69 6e 69 } //1 Linjevogters\telefonboksene.ini
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}