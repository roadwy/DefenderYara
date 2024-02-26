
rule Trojan_Win32_Glupteba_MBEU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MBEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 65 72 75 72 6f 66 61 74 65 76 6f 74 6f 63 75 79 6f 66 6f 73 61 77 } //01 00  kerurofatevotocuyofosaw
		$a_01_1 = {77 69 6d 69 66 65 6d 75 64 61 6c 65 70 75 74 6f 78 } //01 00  wimifemudaleputox
		$a_01_2 = {64 61 6c 69 6e 75 7a 6f 77 75 66 75 77 69 77 61 } //01 00  dalinuzowufuwiwa
		$a_01_3 = {63 75 6b 61 6e 65 6c 65 64 6f 20 68 75 76 61 6c 69 66 75 70 69 76 65 73 20 66 61 74 61 77 6f 64 69 6e 6f 6d 6f 6b 75 6e } //01 00  cukaneledo huvalifupives fatawodinomokun
		$a_01_4 = {67 65 67 65 74 65 68 69 6a 61 79 65 76 75 66 6f 64 75 79 75 6d 61 73 69 79 61 6e 75 6a 75 74 20 6e 61 74 65 6e 61 79 75 79 69 7a 75 70 6f 6e 65 66 61 6e 75 6e 6f 66 61 6c 61 78 61 63 75 20 6c 61 72 75 77 75 77 75 62 75 74 75 6d 69 76 6f 78 6f 78 69 64 20 76 61 7a 6f 67 75 79 75 6a 61 62 6f 7a 75 66 6f 63 } //00 00  gegetehijayevufoduyumasiyanujut natenayuyizuponefanunofalaxacu laruwuwubutumivoxoxid vazoguyujabozufoc
	condition:
		any of ($a_*)
 
}