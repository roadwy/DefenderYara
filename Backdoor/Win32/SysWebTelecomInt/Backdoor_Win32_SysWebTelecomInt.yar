
rule Backdoor_Win32_SysWebTelecomInt{
	meta:
		description = "Backdoor:Win32/SysWebTelecomInt,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 57 65 62 54 65 6c 65 63 6f 6d 2e 44 4c 4c } //5 SysWebTelecom.DLL
		$a_01_1 = {52 61 73 47 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //1 RasGetEntryDialParamsA
		$a_01_2 = {73 65 67 75 72 6f 20 71 75 65 20 64 65 73 65 61 20 64 65 73 63 6f 6e 65 63 74 61 72 73 65 3f } //1 seguro que desea desconectarse?
		$a_01_3 = {45 72 72 6f 72 20 63 6f 6e 65 63 74 61 6e 64 6f 20 63 6f 6e 20 65 6c 20 73 69 67 75 69 65 6e 74 65 20 63 } //1 Error conectando con el siguiente c
		$a_01_4 = {48 61 20 68 61 62 69 64 6f 20 75 6e 20 65 72 72 6f 72 20 69 6e 74 65 6e 74 61 6e 64 6f 20 63 6f 6e 65 63 74 61 72 2e } //1 Ha habido un error intentando conectar.
		$a_01_5 = {73 70 61 6e 69 73 68 2d 64 6f 6d 69 6e 69 63 61 6e 20 72 65 70 75 62 6c 69 63 } //1 spanish-dominican republic
		$a_01_6 = {65 6e 67 6c 69 73 68 2d 74 72 69 6e 69 64 61 64 20 79 20 74 6f 62 61 67 6f } //1 english-trinidad y tobago
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}