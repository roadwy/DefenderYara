
rule Trojan_Win32_Derusbi_H_dha{
	meta:
		description = "Trojan:Win32/Derusbi.H!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {25 73 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 7a 78 46 75 6e 63 74 69 6f 6e 30 30 31 20 25 73 } //10 %s\rundll32.exe %s,zxFunction001 %s
		$a_00_1 = {53 68 61 72 65 53 68 65 6c 6c 20 49 50 20 50 6f 72 74 20 2d 6e 63 } //3 ShareShell IP Port -nc
		$a_00_2 = {50 61 73 73 77 6f 72 64 3a 20 25 73 } //3 Password: %s
		$a_02_3 = {46 75 63 6b 90 03 02 02 4a 50 4b 52 78 78 78 90 00 } //5
		$a_00_4 = {47 6c 6f 62 61 6c 5c 66 63 4b 52 78 78 78 } //5 Global\fcKRxxx
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_02_3  & 1)*5+(#a_00_4  & 1)*5) >=11
 
}