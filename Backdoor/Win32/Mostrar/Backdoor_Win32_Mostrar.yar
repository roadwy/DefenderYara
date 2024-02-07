
rule Backdoor_Win32_Mostrar{
	meta:
		description = "Backdoor:Win32/Mostrar,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 61 63 63 65 73 6f 2e 6d 61 73 6d 69 6e 75 74 6f 73 2e 63 6f 6d } //01 00  http://acceso.masminutos.com
		$a_00_1 = {68 74 74 70 3a 2f 2f 76 69 70 2e 65 73 63 72 69 74 6f 72 69 6f 61 63 74 69 76 6f 2e 63 6f 6d 2f 63 6f 6e 74 72 6f 6c 43 6f 6e 74 69 6e 75 69 64 61 64 2e 68 74 6d } //01 00  http://vip.escritorioactivo.com/controlContinuidad.htm
		$a_01_2 = {52 61 73 44 69 61 6c 41 } //01 00  RasDialA
		$a_00_3 = {45 46 36 44 36 41 45 33 2d 32 36 32 35 2d 34 30 44 36 2d 41 35 41 42 2d 39 32 30 44 46 44 32 44 41 46 38 43 } //01 00  EF6D6AE3-2625-40D6-A5AB-920DFD2DAF8C
		$a_00_4 = {56 65 6e 74 61 6e 61 20 4d 69 6e 69 64 69 61 6c 65 72 } //00 00  Ventana Minidialer
	condition:
		any of ($a_*)
 
}