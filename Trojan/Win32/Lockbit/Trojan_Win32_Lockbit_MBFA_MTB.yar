
rule Trojan_Win32_Lockbit_MBFA_MTB{
	meta:
		description = "Trojan:Win32/Lockbit.MBFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 6f 78 6f 72 61 6d 61 6b 61 6d 61 6d 69 68 75 64 6f 76 75 6a } //01 00  joxoramakamamihudovuj
		$a_01_1 = {6e 75 63 75 73 69 6d 6f 6b 61 64 6f 63 6f 72 69 78 65 68 6f 67 61 } //01 00  nucusimokadocorixehoga
		$a_01_2 = {78 6f 70 61 7a 61 6c 75 6a 69 63 6f 20 73 65 73 6f 6c 65 6d 75 67 69 68 61 6d 65 67 69 72 6f 78 65 63 65 64 20 74 6f 68 61 6b 65 6d 6f 64 65 78 65 78 75 63 69 62 65 6b 75 78 65 64 20 6b 6f 72 75 73 61 68 69 77 65 74 6f 66 65 76 65 78 61 64 6f 70 65 6e 65 62 6f 72 69 76 75 62 65 } //01 00  xopazalujico sesolemugihamegiroxeced tohakemodexexucibekuxed korusahiwetofevexadopeneborivube
		$a_01_3 = {70 65 72 69 6b 69 76 75 74 65 67 6f 73 75 63 69 7a 75 67 65 67 } //01 00  perikivutegosucizugeg
		$a_01_4 = {68 65 6b 65 6e 6f 77 61 74 65 6d 61 62 61 70 61 70 61 6a 69 77 69 77 65 6e 61 66 6f } //00 00  hekenowatemabapapajiwiwenafo
	condition:
		any of ($a_*)
 
}