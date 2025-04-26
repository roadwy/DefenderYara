
rule TrojanProxy_Win32_Dosenjo_A{
	meta:
		description = "TrojanProxy:Win32/Dosenjo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 6e 66 c7 44 24 10 02 00 ff 15 ?? ?? ?? ?? 6a 10 8d 4c 24 10 51 57 } //2
		$a_01_1 = {85 ff 75 01 42 40 3b c1 7c ef 83 fa 05 7d 22 } //2
		$a_01_2 = {63 61 63 68 69 6e 67 44 65 6e 79 3d 00 } //1
		$a_01_3 = {25 73 26 69 70 3d 25 73 26 6d 6f 64 65 3d 25 73 26 64 6c 6c 3d 25 64 00 } //1 猥椦㵰猥洦摯㵥猥搦汬┽d
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}