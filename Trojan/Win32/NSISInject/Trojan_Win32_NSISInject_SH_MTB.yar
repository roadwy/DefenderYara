
rule Trojan_Win32_NSISInject_SH_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {73 74 61 72 62 6f 77 6c 69 6e 65 73 20 74 75 72 6e 6b 65 79 20 73 79 67 65 6d 65 6c 64 69 6e 67 73 } //1 starbowlines turnkey sygemeldings
		$a_81_1 = {68 61 6c 76 6b 75 73 69 6e 65 72 } //1 halvkusiner
		$a_81_2 = {6c 79 73 73 74 79 72 6b 65 6e 20 66 65 6d 61 6c 69 73 65 } //1 lysstyrken femalise
		$a_81_3 = {52 65 67 44 65 6c 65 74 65 4b 65 79 57 } //1 RegDeleteKeyW
		$a_81_4 = {52 65 67 4f 70 65 6e 4b 65 79 45 78 57 } //1 RegOpenKeyExW
		$a_81_5 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //1 SetClipboardData
		$a_81_6 = {4c 6f 61 64 42 69 74 6d 61 70 57 } //1 LoadBitmapW
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}