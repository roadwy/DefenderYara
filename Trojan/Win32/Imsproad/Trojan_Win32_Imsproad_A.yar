
rule Trojan_Win32_Imsproad_A{
	meta:
		description = "Trojan:Win32/Imsproad.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 01 6a 24 e8 90 01 02 ff ff 83 c4 08 6a 64 ff 15 90 01 03 00 6a 02 6a 28 e8 90 01 02 ff ff 83 c4 08 6a 32 ff 15 90 01 03 00 c7 85 e8 fc ff ff 00 00 00 00 0f b6 8d e3 fc ff ff 85 c9 0f 85 90 01 01 02 00 00 6a 01 ff 15 90 01 03 00 83 bd e8 fc ff ff 28 7e 90 00 } //1
		$a_01_1 = {73 74 6f 70 69 6d 73 70 72 65 61 64 65 76 65 6e 74 } //1 stopimspreadevent
		$a_01_2 = {5c 57 69 6e 64 6f 77 73 20 4c 69 76 65 5c 4d 65 73 73 65 6e 67 65 72 5c 6d 73 6e 6d 73 67 72 2e 65 78 65 } //1 \Windows Live\Messenger\msnmsgr.exe
		$a_01_3 = {5c 49 43 51 37 2e 37 5c 49 43 51 2e 65 78 65 } //1 \ICQ7.7\ICQ.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}