
rule Backdoor_Win32_Coolvidoor_A{
	meta:
		description = "Backdoor:Win32/Coolvidoor.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {1b 06 45 53 43 41 50 45 } //1 ؛卅䅃䕐
		$a_00_1 = {43 41 50 53 4c 4f 43 4b 00 } //1
		$a_00_2 = {09 42 41 43 4b 53 50 41 43 45 } //1 䈉䍁卋䅐䕃
		$a_00_3 = {6a 70 67 63 6f 6f 6c 2e } //1 jpgcool.
		$a_01_4 = {4d 53 47 7c 4e 6f 20 73 65 20 70 75 64 6f 20 65 6c 69 6d 69 6e 61 72 20 6c 61 20 63 6c 61 76 65 20 6f 20 65 6c 20 76 61 6c 6f 72 2e } //1 MSG|No se pudo eliminar la clave o el valor.
		$a_01_5 = {4d 53 47 7c 43 6c 61 76 65 20 6f 20 56 61 6c 6f 72 20 65 6c 69 6d 69 6e 61 64 6f 20 63 6f 6e } //1 MSG|Clave o Valor eliminado con
		$a_00_6 = {4c 49 53 54 41 52 56 41 4c 4f 52 45 53 7c } //1 LISTARVALORES|
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}