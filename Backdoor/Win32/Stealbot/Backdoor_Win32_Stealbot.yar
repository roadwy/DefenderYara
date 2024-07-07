
rule Backdoor_Win32_Stealbot{
	meta:
		description = "Backdoor:Win32/Stealbot,SIGNATURE_TYPE_PEHSTR_EXT,ffffff84 00 ffffff82 00 06 00 00 "
		
	strings :
		$a_01_0 = {c6 02 00 03 d0 4f 75 f8 eb 01 41 80 39 20 74 fa 8a 11 80 fa 20 74 17 33 ff 84 d2 74 11 83 ff 0f 7d 0c 88 16 46 47 41 8a 11 80 fa 20 75 eb 33 ff c6 06 00 89 7d 0c eb 01 41 80 39 20 74 fa 8a 19 84 db 74 7e 8b 55 10 03 d7 80 fb 22 75 3b 41 80 39 22 74 fa 8a 19 84 db 74 68 80 fb 22 74 22 8b f2 2b f7 2b 75 10 b8 00 01 00 00 84 db 74 13 3b f0 7d 0f 88 1a 42 46 41 8a 19 80 fb 22 75 ec eb 01 41 80 39 22 74 fa eb 25 80 fb 20 74 20 8b f2 2b f7 2b 75 10 b8 00 01 00 00 84 db 74 10 3b f0 7d 0c 88 1a 42 46 41 8a 19 80 fb 20 75 ec ff 45 0c 03 f8 81 ff 00 0a 00 00 c6 02 00 0f 8c 77 ff ff ff 8b 45 0c } //100
		$a_00_1 = {64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //10 drivers\etc\hosts
		$a_00_2 = {48 61 72 64 77 61 72 65 5c 44 65 73 63 72 69 70 74 69 6f 6e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //10 Hardware\Description\System\CentralProcessor\0
		$a_00_3 = {31 37 32 2e 31 36 00 00 31 39 32 2e 31 36 38 00 } //10
		$a_00_4 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d } //1 application/octet-stream
		$a_00_5 = {3c 74 64 20 61 6c 69 67 6e 3d 22 72 69 67 68 74 22 3e 25 64 4b 62 3c 2f 74 64 3e } //1 <td align="right">%dKb</td>
	condition:
		((#a_01_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=130
 
}