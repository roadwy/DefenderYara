
rule Trojan_Win32_Toorf_B_dha{
	meta:
		description = "Trojan:Win32/Toorf.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 61 00 72 00 74 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 20 00 44 00 6f 00 6e 00 65 00 } //1 Start Keylog Done
		$a_01_1 = {2f 00 53 00 46 00 3f 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 49 00 64 00 3d 00 43 00 6d 00 64 00 52 00 65 00 73 00 75 00 6c 00 74 00 3d 00 } //1 /SF?commandId=CmdResult=
		$a_01_2 = {43 72 65 61 74 65 4d 69 6d 69 32 42 61 74 } //1 CreateMimi2Bat
		$a_01_3 = {7c 7c 7c 43 6f 6d 6d 61 6e 64 20 65 78 65 63 75 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 |||Command executed successfully
		$a_01_4 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 54 6d 70 2a 22 20 26 20 72 6d 64 69 72 20 22 } //1 \Microsoft\Windows\Tmp*" & rmdir "
		$a_03_5 = {5c 42 6f 74 [0-10] 5c 49 73 6d 2e 70 64 62 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2) >=5
 
}