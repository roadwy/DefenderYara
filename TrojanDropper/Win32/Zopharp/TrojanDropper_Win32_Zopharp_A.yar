
rule TrojanDropper_Win32_Zopharp_A{
	meta:
		description = "TrojanDropper:Win32/Zopharp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {23 74 65 6d 70 69 6e 73 74 70 61 74 68 23 5c 50 68 61 72 6d 69 6e 67 20 44 4e 53 2e 73 65 74 } //1 #tempinstpath#\Pharming DNS.set
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 73 79 73 74 65 6d 2e 76 62 73 } //1 C:\Windows\system\system.vbs
		$a_01_2 = {25 73 5c 67 65 72 74 25 69 2e 64 6c 6c } //1 %s\gert%i.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}