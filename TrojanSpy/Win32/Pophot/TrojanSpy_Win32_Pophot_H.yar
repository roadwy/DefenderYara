
rule TrojanSpy_Win32_Pophot_H{
	meta:
		description = "TrojanSpy:Win32/Pophot.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 63 31 36 2e 69 6e 69 00 00 00 00 ff ff ff ff 07 00 00 00 53 74 61 72 74 75 70 00 ff ff ff ff 40 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1
		$a_00_1 = {63 3a 5c 6e 6d 44 65 6c 6d 2e 62 61 74 } //1 c:\nmDelm.bat
		$a_02_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6d 79 63 63 30 38 30 [0-03] 2e 64 6c 6c 20 6d 79 6d 61 69 6e } //1
		$a_00_3 = {7a 73 6d 73 63 63 00 00 ff ff ff ff 0b 00 00 00 5c 75 70 64 61 74 65 2e 65 78 65 00 ff ff ff ff 07 00 00 00 6d 79 63 63 33 32 2e 00 ff ff ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}