
rule Backdoor_Win32_Accesoprivado{
	meta:
		description = "Backdoor:Win32/Accesoprivado,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 29 20 45 6c 20 73 65 72 76 69 63 69 6f 20 61 6c 20 71 75 65 20 76 61 20 61 20 61 63 63 65 64 65 72 20 70 75 65 64 65 20 63 6f 6e 74 65 6e 65 72 } //3 3) El servicio al que va a acceder puede contener
		$a_01_1 = {30 2e 39 31 20 65 75 72 6f 73 2f 6d 69 6e 75 74 6f 20 65 6e 20 68 6f 72 61 72 69 6f 20 6e 6f 72 6d 61 6c 2e 20 } //5 0.91 euros/minuto en horario normal. 
		$a_01_2 = {52 61 73 53 65 74 45 6e 74 72 79 50 72 6f 70 65 72 74 69 65 73 41 } //1 RasSetEntryPropertiesA
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=9
 
}