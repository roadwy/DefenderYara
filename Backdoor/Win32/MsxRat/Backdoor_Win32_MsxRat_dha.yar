
rule Backdoor_Win32_MsxRat_dha{
	meta:
		description = "Backdoor:Win32/MsxRat!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 73 78 53 74 64 75 4f 6e 65 53 74 61 72 74 2e 63 6f 6d } //1 MsxStduOneStart.com
		$a_01_1 = {6d 73 78 52 41 54 31 2e 30 } //2 msxRAT1.0
		$a_01_2 = {6d 73 78 2e 65 78 65 } //1 msx.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}