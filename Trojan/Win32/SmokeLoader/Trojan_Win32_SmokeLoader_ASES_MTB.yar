
rule Trojan_Win32_SmokeLoader_ASES_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 00 7a 00 75 00 72 00 65 00 62 00 69 00 7a 00 61 00 6a 00 69 00 76 00 65 00 62 00 69 00 6c 00 65 00 64 00 69 00 6b 00 } //01 00  tzurebizajivebiledik
		$a_01_1 = {54 00 61 00 76 00 75 00 7a 00 69 00 72 00 65 00 70 00 65 00 66 00 6f 00 7a 00 61 00 6b 00 20 00 79 00 75 00 6e 00 20 00 64 00 65 00 6c 00 6f 00 62 00 6f 00 70 00 61 00 78 00 75 00 23 00 4d 00 65 00 64 00 69 00 20 00 6d 00 75 00 67 00 65 00 6e 00 75 00 78 00 20 00 62 00 61 00 77 00 69 00 6c 00 75 00 76 00 6f 00 70 00 6f 00 63 00 65 00 70 00 20 00 76 00 69 00 6e 00 6f 00 6d 00 69 00 6e 00 75 00 } //01 00  Tavuzirepefozak yun delobopaxu#Medi mugenux bawiluvopocep vinominu
		$a_01_2 = {62 00 6b 00 61 00 6b 00 61 00 6b 00 65 00 66 00 61 00 67 00 61 00 78 00 65 00 70 00 69 00 6a 00 6f 00 73 00 } //01 00  bkakakefagaxepijos
		$a_01_3 = {5a 00 61 00 73 00 61 00 62 00 69 00 78 00 6f 00 62 00 65 00 7a 00 6f 00 7a 00 20 00 62 00 65 00 73 00 6f 00 76 00 61 00 62 00 } //01 00  Zasabixobezoz besovab
		$a_01_4 = {79 00 65 00 74 00 6f 00 6e 00 6f 00 64 00 69 00 76 00 6f 00 68 00 61 00 66 00 6f 00 74 00 69 00 70 00 75 00 6b 00 6f 00 79 00 61 00 76 00 69 00 72 00 20 00 64 00 61 00 73 00 61 00 63 00 6f 00 6b 00 6f 00 73 00 65 00 76 00 69 00 73 00 6f 00 63 00 75 00 20 00 6b 00 6f 00 63 00 65 00 64 00 65 00 63 00 65 00 73 00 69 00 6b 00 61 00 67 00 6f 00 79 00 75 00 66 00 6f 00 68 00 69 00 62 00 69 00 68 00 69 00 63 00 61 00 7a 00 69 00 68 00 6f 00 7a 00 6f 00 20 00 6d 00 69 00 74 00 75 00 64 00 20 00 68 00 75 00 78 00 65 00 64 00 75 00 72 00 61 00 78 00 69 00 76 00 6f 00 73 00 75 00 79 00 65 00 77 00 61 00 63 00 } //00 00  yetonodivohafotipukoyavir dasacokosevisocu kocedecesikagoyufohibihicazihozo mitud huxeduraxivosuyewac
	condition:
		any of ($a_*)
 
}