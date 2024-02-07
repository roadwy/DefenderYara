
rule TrojanSpy_Win32_Banker_UUB{
	meta:
		description = "TrojanSpy:Win32/Banker.UUB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 08 00 00 05 00 "
		
	strings :
		$a_01_0 = {ff ff ff ff 07 00 00 00 54 6f 4d 61 69 6c 3d 00 ff ff ff ff 06 00 00 00 26 55 73 65 72 3d 00 00 ff ff ff ff 06 00 00 00 26 50 61 73 73 3d 00 00 ff ff ff ff 08 00 00 00 26 53 65 72 76 65 72 3d 00 00 00 00 ff ff ff ff 09 00 00 00 26 57 69 6e 4e 61 6d 65 3d 00 00 00 ff ff ff ff 0b 00 00 00 26 57 69 6e 42 61 6e 42 65 6e 3d 00 ff ff ff ff 07 00 00 00 53 65 6e 64 20 4f 4b 00 51 } //05 00 
		$a_01_1 = {ff ff ff ff 07 00 00 00 54 6f 4d 61 69 6c 3d 00 ff ff ff ff 06 00 00 00 26 55 73 65 72 3d 00 00 ff ff ff ff 06 00 00 00 26 50 61 73 73 3d 00 00 ff ff ff ff 06 00 00 00 26 52 6f 6c 65 3d 00 00 ff ff ff ff 08 00 00 00 26 53 65 72 76 65 72 3d 00 00 00 00 ff ff ff ff 09 00 00 00 26 57 69 6e 4e 61 6d 65 3d 00 00 00 ff ff ff ff 0c 00 00 00 26 57 69 6e 45 64 69 74 69 6f 6e 3d 00 00 00 00 ff ff ff ff 07 00 00 00 53 65 6e 64 20 4f 4b 00 } //01 00 
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_3 = {52 75 6e 74 69 6d 65 20 65 72 72 6f 72 20 20 20 20 20 61 74 20 30 30 30 30 30 30 30 30 } //01 00  Runtime error     at 00000000
		$a_01_4 = {48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //01 00  HttpOpenRequestA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //01 00  InternetConnectA
		$a_01_6 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 } //01 00  GetStartupInfoA
		$a_01_7 = {53 79 73 52 65 41 6c 6c 6f 63 53 74 72 69 6e 67 4c 65 6e } //00 00  SysReAllocStringLen
	condition:
		any of ($a_*)
 
}