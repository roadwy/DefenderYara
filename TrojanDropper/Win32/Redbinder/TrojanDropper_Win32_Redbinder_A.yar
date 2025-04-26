
rule TrojanDropper_Win32_Redbinder_A{
	meta:
		description = "TrojanDropper:Win32/Redbinder.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 20 69 73 20 52 65 64 42 69 6e 64 65 52 } //5 This is RedBindeR
		$a_01_1 = {52 65 64 42 69 6e 64 65 72 } //3 RedBinder
		$a_01_2 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 2e 65 78 65 } //2 C:\Windows\system.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}