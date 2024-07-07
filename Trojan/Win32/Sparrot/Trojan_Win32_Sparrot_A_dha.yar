
rule Trojan_Win32_Sparrot_A_dha{
	meta:
		description = "Trojan:Win32/Sparrot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 62 75 66 66 65 72 20 6c 65 6e 67 74 68 20 69 73 6e 6f 74 20 65 6e 6f 75 67 68 74 21 } //1 The buffer length isnot enought!
		$a_01_1 = {4d 61 6c 6c 6f 63 20 45 72 72 6f 72 } //1 Malloc Error
		$a_01_2 = {4f 70 65 6e 20 4f 52 20 57 72 69 74 65 20 46 69 6c 65 20 45 72 72 6f 72 } //1 Open OR Write File Error
		$a_01_3 = {2f 75 70 6c 6f 61 64 2e 70 68 70 } //1 /upload.php
		$a_01_4 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 66 69 6c 65 22 3b 20 66 69 6c 65 6e 61 6d 65 3d } //1 Content-Disposition: form-data; name="file"; filename=
		$a_00_5 = {53 70 61 72 72 6f 77 44 6c 6c 2e 64 6c 6c } //1 SparrowDll.dll
		$a_01_6 = {4d 79 41 67 65 6e 74 } //1 MyAgent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}