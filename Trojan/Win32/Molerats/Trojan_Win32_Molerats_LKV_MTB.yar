
rule Trojan_Win32_Molerats_LKV_MTB{
	meta:
		description = "Trojan:Win32/Molerats.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 79 2e 71 69 77 69 2e 63 6f 6d 2f 56 61 6c 65 72 79 69 2d } //1 my.qiwi.com/Valeryi-
		$a_01_1 = {4b 41 42 78 36 34 5c 73 79 73 74 65 6d 70 78 2e 65 78 65 } //1 KABx64\systempx.exe
		$a_01_2 = {70 72 6f 63 65 73 73 5f 6c 69 73 74 } //1 process_list
		$a_01_3 = {61 76 70 2e 65 78 65 } //1 avp.exe
		$a_01_4 = {6e 6f 72 74 6f 6e 2e 65 78 65 } //1 norton.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}