
rule TrojanSpy_Win32_Kratos_A_bit{
	meta:
		description = "TrojanSpy:Win32/Kratos.A!bit,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 70 69 2f 67 61 74 65 2e 70 68 70 3f 68 77 69 64 3d 25 73 26 70 61 73 73 77 6f 72 64 73 3d 25 64 26 63 6f 6f 6b 69 65 73 3d 25 64 26 66 6f 72 6d 73 3d 25 64 26 63 61 72 64 73 3d 25 64 26 64 65 73 6b 74 6f 70 3d 25 64 } //1 api/gate.php?hwid=%s&passwords=%d&cookies=%d&forms=%d&cards=%d&desktop=%d
		$a_01_1 = {26 77 61 6c 6c 65 74 73 3d 25 64 26 74 65 6c 65 67 72 61 6d 3d 25 64 26 73 74 65 61 6d 3d 25 64 26 66 69 6c 65 7a 69 6c 6c 61 3d 25 64 } //1 &wallets=%d&telegram=%d&steam=%d&filezilla=%d
		$a_01_2 = {58 46 78 54 59 33 4a 6c 5a 57 35 7a 61 47 39 30 4c 6d 4a 74 63 41 3d 3d } //1 XFxTY3JlZW5zaG90LmJtcA==
		$a_01_3 = {58 46 78 58 59 57 78 73 5a 58 52 7a } //1 XFxXYWxsZXRz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}