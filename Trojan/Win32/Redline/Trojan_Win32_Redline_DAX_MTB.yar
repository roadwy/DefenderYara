
rule Trojan_Win32_Redline_DAX_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {48 65 6c 66 72 6c 6f } //1 Helfrlo
		$a_01_1 = {48 77 77 65 65 6c 6c 6f } //1 Hwweello
		$a_01_2 = {48 65 6c 66 68 36 72 6c 6f } //1 Helfh6rlo
		$a_01_3 = {48 77 77 7a 78 41 65 65 6c 6c 6f } //1 HwwzxAeello
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 73 5c 44 6f 63 75 6d 65 6e 74 73 5c 77 72 6f 66 6c 6d 6a 6b 5c 6f 75 74 70 75 74 2e 70 64 62 } //1 Downloads\Documents\wroflmjk\output.pdb
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 73 5c 4e 65 77 50 75 62 6c 69 73 68 5c 6b 67 61 77 6f 68 32 30 70 35 76 5c 6f 75 74 70 75 74 2e 70 64 62 } //1 Downloads\NewPublish\kgawoh20p5v\output.pdb
		$a_03_6 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-20] 5c 41 70 70 4c 61 75 6e 63 68 2e 65 78 65 } //1
		$a_01_7 = {2e 55 41 5a } //1 .UAZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}