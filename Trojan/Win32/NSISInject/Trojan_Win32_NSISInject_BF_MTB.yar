
rule Trojan_Win32_NSISInject_BF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 61 72 61 76 61 6e 74 5c 53 74 6f 70 70 61 67 65 5c 73 79 6c 6c 61 62 6f 67 72 61 6d 5c 43 69 74 72 75 6c 6c 69 6e 2e 69 6e 69 } //01 00  Paravant\Stoppage\syllabogram\Citrullin.ini
		$a_01_1 = {48 75 6c 73 74 65 72 5c 41 67 72 61 72 6b 6f 6e 6f 6d 65 72 5c 44 69 73 70 72 65 61 64 65 72 2e 64 6c 6c } //01 00  Hulster\Agrarkonomer\Dispreader.dll
		$a_01_2 = {53 75 6e 73 65 74 73 5c 48 6f 76 65 64 6b 6f 72 74 73 5c 44 79 62 66 72 6f 73 74 65 6e 73 5c 50 6c 61 74 65 72 65 73 71 75 65 2e 53 74 61 } //01 00  Sunsets\Hovedkorts\Dybfrostens\Plateresque.Sta
		$a_01_3 = {61 70 70 6c 69 6b 65 72 65 5c 53 70 65 6c 6c 77 6f 72 64 2e 73 65 6d } //01 00  applikere\Spellword.sem
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4e 6f 6e 6e 61 74 69 76 65 6c 79 5c 54 75 72 64 69 6e 65 } //00 00  Software\Nonnatively\Turdine
	condition:
		any of ($a_*)
 
}