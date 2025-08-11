
rule Trojan_Win32_GuLoader_RBI_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 75 72 6c 69 6e 67 74 6f 6e 20 52 65 73 6f 75 72 63 65 73 20 49 6e 63 2e } //1 Burlington Resources Inc.
		$a_81_1 = {42 6f 77 61 74 65 72 20 49 6e 63 6f 72 70 6f 72 61 74 65 64 } //1 Bowater Incorporated
		$a_81_2 = {53 69 65 62 65 6c 20 53 79 73 74 65 6d 73 20 49 6e 63 } //1 Siebel Systems Inc
		$a_81_3 = {4c 61 6e 64 73 74 61 72 20 53 79 73 74 65 6d 20 49 6e 63 2e } //1 Landstar System Inc.
		$a_81_4 = {66 69 65 6e 64 6c 69 6e 65 73 73 20 68 6f 72 72 6f 72 66 75 6c 2e 65 78 65 } //1 fiendliness horrorful.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_RBI_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 72 65 70 65 74 72 70 72 5c 74 61 62 6c 6f 69 64 61 76 69 73 5c 70 6f 72 74 73 6d 6f 75 74 68 } //1 \repetrpr\tabloidavis\portsmouth
		$a_81_1 = {2d 5c 62 65 74 61 67 65 6c 73 65 72 73 5c 73 74 69 66 69 6e 64 65 72 65 6e 73 2e 6a 70 67 } //1 -\betagelsers\stifinderens.jpg
		$a_81_2 = {25 62 6c 67 65 64 65 25 5c 68 75 6d 6d 65 72 65 73 5c 75 6e 73 61 64 } //1 %blgede%\hummeres\unsad
		$a_81_3 = {37 5c 66 79 6c 6b 65 5c 73 63 61 70 68 6f 63 65 72 69 74 65 2e 74 78 74 } //1 7\fylke\scaphocerite.txt
		$a_81_4 = {66 75 6d 20 65 73 70 61 76 65 6c 2e 65 78 65 } //1 fum espavel.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}