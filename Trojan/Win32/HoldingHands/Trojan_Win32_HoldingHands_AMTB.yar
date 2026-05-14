
rule Trojan_Win32_HoldingHands_AMTB{
	meta:
		description = "Trojan:Win32/HoldingHands!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {44 3a 5c 57 6f 72 6b 73 70 61 63 65 5c 48 6f 6c 64 69 6e 67 48 61 6e 64 73 2d 64 65 76 65 6c 6f 70 5c 48 6f 6c 64 69 6e 67 48 61 6e 64 73 2d 64 65 76 65 6c 6f 70 5c 44 6f 6f 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 52 75 6e 5f 4e 65 77 2e 70 64 62 } //D:\Workspace\HoldingHands-develop\HoldingHands-develop\Door\x64\Release\Run_New.pdb  3
		$a_80_1 = {44 3a 5c 57 6f 72 6b 73 70 61 63 65 5c 48 6f 6c 64 69 6e 67 48 61 6e 64 73 2d 64 65 76 65 6c 6f 70 5c 48 6f 6c 64 69 6e 67 48 61 6e 64 73 2d 64 65 76 65 6c 6f 70 5c 44 6f 6f 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 42 61 63 6b 44 6f 6f 72 2e 70 64 62 } //D:\Workspace\HoldingHands-develop\HoldingHands-develop\Door\x64\Release\BackDoor.pdb  3
		$a_80_2 = {43 68 65 6e 67 64 75 20 4c 69 6e 67 78 75 20 54 65 63 68 6e 6f 6c 6f 67 79 20 43 6f 2e 2c 20 4c 74 64 2e 30 } //Chengdu Lingxu Technology Co., Ltd.0  1
		$a_80_3 = {24 53 68 61 6e 67 68 61 69 20 4c 69 61 6e 64 75 20 54 65 63 68 6e 6f 6c 6f 67 79 20 43 6f 2e 2c 20 4c 74 64 2e 31 } //$Shanghai Liandu Technology Co., Ltd.1  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}