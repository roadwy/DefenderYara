
rule Backdoor_Win64_Plugx{
	meta:
		description = "Backdoor:Win64/Plugx,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f 00 54 00 65 00 61 00 6d 00 56 00 69 00 65 00 77 00 65 00 72 00 5f 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 } //1 _TeamViewer_Monitor
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 70 00 61 00 72 00 61 00 6d 00 } //1 SOFTWARE\param
		$a_01_2 = {4f 00 6e 00 4c 00 69 00 6e 00 65 00 50 00 69 00 64 00 } //1 OnLinePid
		$a_01_3 = {5c 00 41 00 70 00 70 00 43 00 6f 00 6d 00 70 00 61 00 74 00 46 00 6c 00 61 00 67 00 73 00 5c 00 43 00 75 00 73 00 74 00 6f 00 6d 00 5c 00 } //1 \AppCompatFlags\Custom\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}