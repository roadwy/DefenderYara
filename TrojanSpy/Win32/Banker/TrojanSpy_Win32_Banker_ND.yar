
rule TrojanSpy_Win32_Banker_ND{
	meta:
		description = "TrojanSpy:Win32/Banker.ND,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {3c 6b 65 79 73 74 6f 72 65 66 69 6c 65 20 4b 45 59 46 49 4c 45 3d } //01 00  <keystorefile KEYFILE=
		$a_01_1 = {75 73 65 72 69 6e 69 74 2e 65 78 65 2c 73 76 } //01 00  userinit.exe,sv
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 69 62 61 6e 6b 2e } //01 00  https://ibank.
		$a_01_3 = {75 70 64 61 74 65 2e 70 68 70 3f 6f 73 3d } //01 00  update.php?os=
		$a_01_4 = {63 6d 64 2e 65 78 65 20 2f 6b 20 65 63 68 6f 20 79 7c 20 63 61 63 6c 73 } //00 00  cmd.exe /k echo y| cacls
	condition:
		any of ($a_*)
 
}