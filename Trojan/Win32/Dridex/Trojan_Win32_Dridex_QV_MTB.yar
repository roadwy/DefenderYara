
rule Trojan_Win32_Dridex_QV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.QV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //3 RTTYEBHUY.pdb
		$a_81_1 = {77 69 6c 6c 4f 45 66 58 } //3 willOEfX
		$a_81_2 = {57 69 6e 53 43 61 72 64 2e 64 6c 6c } //3 WinSCard.dll
		$a_81_3 = {49 6e 74 65 72 6e 65 74 53 65 74 53 74 61 74 75 73 43 61 6c 6c 62 61 63 6b } //3 InternetSetStatusCallback
		$a_81_4 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //3 kernel32.Sleep
		$a_81_5 = {4a 64 69 64 62 72 6f 77 73 65 72 } //3 Jdidbrowser
		$a_81_6 = {57 49 4e 53 50 4f 4f 4c 2e 44 52 56 } //3 WINSPOOL.DRV
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}