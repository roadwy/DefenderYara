
rule Trojan_Win32_Ramnit_A_vnc{
	meta:
		description = "Trojan:Win32/Ramnit.A!vnc,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 6e 63 2e 64 6c 6c 00 43 6f 6d 6d 61 6e 64 52 6f 75 74 69 6e 65 00 4d 6f 64 75 6c 65 43 6f 64 65 00 53 74 61 72 74 52 6f 75 74 69 6e 65 00 53 74 6f 70 52 6f 75 74 69 6e 65 00 } //1
		$a_01_1 = {85 c0 74 6e 83 3c 24 4e 75 68 6a 00 8d 44 24 08 50 68 8d 49 37 29 e8 58 9f ff ff 6a 4c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}