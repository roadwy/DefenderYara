
rule TrojanDropper_Win32_Yenfhur_A{
	meta:
		description = "TrojanDropper:Win32/Yenfhur.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6b 00 75 00 73 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 2b 00 6d 00 75 00 6b 00 6d 00 69 00 6c 00 2e 00 64 00 6c 00 6c 00 2b 00 76 00 75 00 6d 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 kuser.dll+mukmil.dll+vumer.dll
		$a_01_1 = {72 65 73 73 69 67 6e 61 6d 65 } //1 ressigname
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}