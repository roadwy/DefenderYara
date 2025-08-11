
rule Trojan_Win32_Guloader_SLHE_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 79 70 69 63 6f 6e 5c 4b 75 6f 6d 69 6e 74 61 6e 67 } //2 Typicon\Kuomintang
		$a_01_1 = {53 70 69 6c 64 65 76 61 6e 64 73 63 69 72 6b 75 6c 72 65 73 32 35 2e 67 65 6e } //2 Spildevandscirkulres25.gen
		$a_01_2 = {74 72 61 66 69 6b 65 6c 65 76 65 72 2e 69 6e 69 } //2 trafikelever.ini
		$a_01_3 = {5c 73 75 62 73 79 73 74 65 6d 73 5c 72 65 63 6f 6e 63 69 6c 69 61 62 69 6c 69 74 79 2e 68 74 6d } //2 \subsystems\reconciliability.htm
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}