
rule Backdoor_Win32_Gamloby_A_bit{
	meta:
		description = "Backdoor:Win32/Gamloby.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 24 4d 53 52 65 63 79 63 6c 65 2e 42 69 6e 5c 4d 69 63 72 6f 52 65 63 79 63 6c 65 2e 64 6c 6c } //10 C:\$MSRecycle.Bin\MicroRecycle.dll
		$a_01_1 = {43 3a 5c 24 4d 53 52 65 63 79 63 6c 65 2e 42 69 6e 5c 54 73 69 53 65 72 76 69 63 65 2e 65 78 65 } //10 C:\$MSRecycle.Bin\TsiService.exe
		$a_01_2 = {43 3a 5c 24 4d 53 52 65 63 79 63 6c 65 2e 42 69 6e 5c 78 70 2e 69 6f 73 } //10 C:\$MSRecycle.Bin\xp.ios
		$a_01_3 = {5c 52 65 6d 6f 74 65 44 6c 6c 5c 72 65 6c 65 61 73 65 5c 52 65 6d 6f 74 65 44 6c 6c 2e 70 64 62 } //1 \RemoteDll\release\RemoteDll.pdb
		$a_01_4 = {73 63 20 63 6f 6e 66 69 67 20 25 73 20 73 74 61 72 74 3d 20 61 75 74 6f } //1 sc config %s start= auto
		$a_01_5 = {8a 1c 06 88 1c 01 88 14 06 0f b6 1c 01 0f b6 d2 03 da 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f b6 14 03 30 14 2f 83 c7 01 3b 7c 24 1c 72 } //1
		$a_03_6 = {68 02 20 00 00 68 90 01 03 00 ff 15 90 01 03 00 6a 00 68 90 01 03 00 6a 00 8d 84 24 90 01 02 00 00 50 68 90 01 03 00 6a 00 ff 15 90 01 03 00 6a 00 ff 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=32
 
}