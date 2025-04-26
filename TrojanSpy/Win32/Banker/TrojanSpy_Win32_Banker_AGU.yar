
rule TrojanSpy_Win32_Banker_AGU{
	meta:
		description = "TrojanSpy:Win32/Banker.AGU,SIGNATURE_TYPE_PEHSTR_EXT,ffffffaa 00 ffffffa0 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 61 73 73 77 6f 72 64 3d 61 64 6d 31 30 32 30 33 30 } //50 Password=adm102030
		$a_01_1 = {49 44 3d 61 63 65 73 73 6f 61 64 69 6d 69 73 74 72 61 74 69 76 6f } //50 ID=acessoadimistrativo
		$a_01_2 = {53 6f 75 72 63 65 3d 6d 73 73 71 6c 2e 61 63 65 73 73 6f 61 64 69 6d 69 73 74 72 61 74 69 76 6f 2e 6b 69 6e 67 68 6f 73 74 2e 6e 65 74 2c 31 34 33 33 } //50 Source=mssql.acessoadimistrativo.kinghost.net,1433
		$a_01_3 = {64 65 6c 65 74 65 20 66 72 6f 6d 20 54 41 42 5f 30 30 31 5f 54 41 42 } //10 delete from TAB_001_TAB
		$a_01_4 = {2f 6d 69 6e 69 6d 69 7a 65 64 2f 72 65 67 72 75 6d } //10 /minimized/regrum
	condition:
		((#a_01_0  & 1)*50+(#a_01_1  & 1)*50+(#a_01_2  & 1)*50+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=160
 
}