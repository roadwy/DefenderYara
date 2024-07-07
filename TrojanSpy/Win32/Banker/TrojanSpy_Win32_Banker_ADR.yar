
rule TrojanSpy_Win32_Banker_ADR{
	meta:
		description = "TrojanSpy:Win32/Banker.ADR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 69 6e 67 2f 61 63 63 6f 75 6e 74 2e 61 73 70 3f 69 64 3d } //3 /ing/account.asp?id=
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 73 68 69 6d 67 76 77 2e 64 6c 6c 2c 49 6d 61 67 65 56 69 65 77 5f 46 75 6c 6c 73 63 72 65 65 6e 20 43 3a 5c } //2 rundll32.exe shimgvw.dll,ImageView_Fullscreen C:\
		$a_01_2 = {26 37 6e 61 6d 65 3d 65 62 61 6e 6b 44 65 70 6f 73 69 74 46 6f 72 6d 20 61 63 74 69 6f 6e 3d } //3 &7name=ebankDepositForm action=
		$a_01_3 = {43 6d 73 73 20 31 2e 30 20 42 61 74 65 } //4 Cmss 1.0 Bate
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*4) >=12
 
}