
rule Backdoor_Win32_Rmtsvc_C_bit{
	meta:
		description = "Backdoor:Win32/Rmtsvc.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 69 6e 64 69 70 00 00 73 76 72 70 6f 72 74 00 73 65 74 74 69 6e 67 00 73 74 6f 70 00 00 00 00 72 75 6e } //1
		$a_01_1 = {5b 75 70 6c 6f 61 64 5d 20 69 70 3d 25 73 20 2d 20 25 73 20 75 70 6c 6f 61 64 20 25 73 } //1 [upload] ip=%s - %s upload %s
		$a_03_2 = {73 65 6e 64 69 6e 67 [0-10] 2e 6a 70 67 } //1
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 53 65 72 76 69 63 65 73 } //1 Software\Microsoft\Windows\CurrentVersion\RunServices
		$a_03_4 = {6a 40 68 00 10 00 00 53 6a 00 55 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84 } //1
		$a_03_5 = {6a 00 6a 00 56 53 6a 00 6a 00 55 ff 15 ?? ?? ?? ?? 8b d8 85 db 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}