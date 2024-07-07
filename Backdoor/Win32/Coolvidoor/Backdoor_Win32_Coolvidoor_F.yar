
rule Backdoor_Win32_Coolvidoor_F{
	meta:
		description = "Backdoor:Win32/Coolvidoor.F,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6f 6c 76 69 62 65 73 } //2 coolvibes
		$a_02_1 = {43 6f 6f 6c 90 02 03 73 65 72 76 65 72 90 00 } //2
		$a_00_2 = {4d 53 47 7c 55 6e 69 64 61 64 20 6e 6f 20 61 63 63 65 73 69 62 6c 65 21 } //1 MSG|Unidad no accesible!
		$a_00_3 = {47 45 54 46 49 4c 45 7c } //1 GETFILE|
		$a_00_4 = {53 45 52 56 49 44 4f 52 7c 49 4e 46 4f 7c } //1 SERVIDOR|INFO|
		$a_00_5 = {56 45 52 55 4e 49 44 41 44 45 53 7c } //1 VERUNIDADES|
		$a_00_6 = {4c 49 53 54 41 52 41 52 43 48 49 56 4f 53 7c } //1 LISTARARCHIVOS|
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}