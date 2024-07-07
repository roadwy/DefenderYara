
rule Trojan_Win32_Koobface_J{
	meta:
		description = "Trojan:Win32/Koobface.J,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0f 00 0d 00 00 "
		
	strings :
		$a_01_0 = {31 f6 b9 0f 00 00 00 56 49 75 fc 6a 20 8d 9d 44 ff ff ff 53 ff 15 } //5
		$a_01_1 = {72 46 87 d9 2b d9 fc 51 c1 e9 02 f3 a5 59 83 e1 03 f3 a4 5e 8b cb 51 c1 e9 02 f3 a5 59 83 e1 03 f3 a4 8b bd 78 ff ff ff 8b f2 87 74 3d 98 e8 } //5
		$a_01_2 = {63 68 61 74 2f 73 65 6e 64 2e 70 68 70 } //1 chat/send.php
		$a_01_3 = {75 70 64 61 74 65 73 74 61 74 75 73 2e 70 68 70 } //1 updatestatus.php
		$a_01_4 = {75 66 69 2f 6d 6f 64 69 66 79 2e 70 68 70 } //1 ufi/modify.php
		$a_01_5 = {26 78 68 70 63 5f 6d 65 73 73 61 67 65 } //1 &xhpc_message
		$a_01_6 = {26 6d 73 67 5f 74 65 78 74 3d } //1 &msg_text=
		$a_01_7 = {26 74 6f 5f 6f 66 66 6c 69 6e 65 3d } //1 &to_offline=
		$a_01_8 = {26 61 64 64 5f 63 6f 6d 6d 65 6e 74 5f 74 65 78 74 5f 74 65 78 74 3d } //1 &add_comment_text_text=
		$a_01_9 = {26 6d 6f 6f 64 3d } //1 &mood=
		$a_01_10 = {53 61 76 65 53 74 61 74 75 73 2e 61 73 68 78 } //1 SaveStatus.ashx
		$a_01_11 = {26 65 5f 66 6f 72 6d 61 74 3d } //1 &e_format=
		$a_01_12 = {26 65 5f 6d 65 73 73 61 67 65 3d } //1 &e_message=
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=15
 
}