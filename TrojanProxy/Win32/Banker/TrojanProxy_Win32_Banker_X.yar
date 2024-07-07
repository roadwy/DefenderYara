
rule TrojanProxy_Win32_Banker_X{
	meta:
		description = "TrojanProxy:Win32/Banker.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 61 6d 70 69 6e 61 73 65 6d 66 6f 63 6f 2e 63 6f 6d 2e 62 72 2f 69 6d 61 67 65 73 2f 90 02 15 2e 70 61 63 90 00 } //1
		$a_00_1 = {32 30 30 2e 39 38 2e 31 36 32 2e 31 32 36 2f 47 65 72 61 44 61 64 6f 73 2e 70 68 70 } //1 200.98.162.126/GeraDados.php
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}