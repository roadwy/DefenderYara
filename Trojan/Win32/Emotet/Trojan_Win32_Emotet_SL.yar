
rule Trojan_Win32_Emotet_SL{
	meta:
		description = "Trojan:Win32/Emotet.SL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 6b 00 61 00 76 00 61 00 20 00 4c 00 6f 00 73 00 74 00 57 00 68 00 6f 00 73 00 69 00 67 00 68 00 74 00 20 00 53 00 74 00 69 00 63 00 6b 00 73 00 6c 00 61 00 76 00 65 00 } //1 Skava LostWhosight Stickslave
		$a_01_1 = {63 3a 5c 53 65 6c 66 5c 50 69 74 63 68 5c 4c 61 75 67 68 5c 50 6f 73 73 69 62 6c 65 53 65 63 74 69 6f 6e 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}