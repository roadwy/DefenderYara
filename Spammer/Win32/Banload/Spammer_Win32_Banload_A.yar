
rule Spammer_Win32_Banload_A{
	meta:
		description = "Spammer:Win32/Banload.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 41 5f 64 6f 4d 53 4e 54 69 6d 65 72 } //1 AA_doMSNTimer
		$a_01_1 = {4c 69 73 74 61 4d 53 4e 45 6e 76 69 61 72 } //1 ListaMSNEnviar
		$a_01_2 = {41 41 5f 64 61 74 61 48 54 4d 4c 31 } //1 AA_dataHTML1
		$a_01_3 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 6d 73 6e 5f 6c 69 76 65 72 73 2e 65 78 65 } //1 C:\Arquivos de programas\msn_livers.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}