
rule Trojan_Win64_Filisto_C_dha{
	meta:
		description = "Trojan:Win64/Filisto.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6d 69 64 69 6d 61 70 2e 44 72 69 76 65 72 50 72 6f 63 } //1 c:\windows\system32\midimap.DriverProc
		$a_01_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6d 69 64 69 6d 61 70 2e 6d 6f 64 4d 65 73 73 61 67 65 } //1 c:\windows\system32\midimap.modMessage
		$a_01_2 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 6d 69 64 69 6d 61 70 2e 6d 6f 64 6d 43 61 6c 6c 62 61 63 6b } //1 c:\windows\system32\midimap.modmCallback
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}