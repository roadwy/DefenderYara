
rule Trojan_Win64_RollerCoaster_D_dha{
	meta:
		description = "Trojan:Win64/RollerCoaster.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6f 74 6f 4c 69 6e 65 43 6f 6c 2e 65 78 65 } //2 GotoLineCol.exe
		$a_01_1 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 5c 00 47 00 6f 00 74 00 6f 00 4c 00 69 00 6e 00 65 00 43 00 6f 00 6c 00 2e 00 69 00 6e 00 69 00 } //1 C:\WINDOWS\\GotoLineCol.ini
		$a_01_2 = {62 6f 6f 74 2e 69 6e 69 7c } //1 boot.ini|
		$a_01_3 = {47 65 6e 65 72 61 6c 00 43 6f 6e 74 65 6e 74 00 4f 66 66 73 65 74 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}