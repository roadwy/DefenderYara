
rule Trojan_Win32_Qhost_EU{
	meta:
		description = "Trojan:Win32/Qhost.EU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 ee 73 74 73 [0-10] (23 20 43 6f 70 79 72 69 67 68 74|4d 79 47 75 65 73 74 73) } //1
		$a_00_1 = {2e 72 75 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}