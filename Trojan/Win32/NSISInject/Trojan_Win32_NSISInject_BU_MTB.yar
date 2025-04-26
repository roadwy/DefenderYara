
rule Trojan_Win32_NSISInject_BU_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 65 73 74 79 72 65 6c 73 65 72 5c 55 6e 74 61 75 67 68 74 6e 65 73 73 5c 41 6e 74 69 72 65 6e 74 65 72 2e 69 6e 69 } //1 Bestyrelser\Untaughtness\Antirenter.ini
		$a_01_1 = {54 69 6c 73 74 6e 69 6e 67 73 66 72 69 5c 50 72 65 63 6f 6e 63 65 73 73 69 6f 6e 73 5c 50 75 72 73 75 69 74 5c 43 61 75 73 74 69 63 69 73 65 73 2e 69 6e 69 } //1 Tilstningsfri\Preconcessions\Pursuit\Causticises.ini
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 43 65 6e 74 72 61 6c 65 72 5c 41 66 64 72 61 6d 61 74 69 73 65 72 69 6e 67 65 6e 73 34 31 5c 54 72 79 6b 73 74 62 6e 69 6e 67 } //1 Software\Centraler\Afdramatiseringens41\Trykstbning
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 52 65 73 74 61 75 72 65 72 69 6e 67 65 6e 73 } //1 Software\Restaureringens
		$a_01_4 = {44 75 62 6c 65 72 69 6e 67 65 72 6e 65 73 } //1 Dubleringernes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}