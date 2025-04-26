
rule Trojan_Win32_Emotet_EC{
	meta:
		description = "Trojan:Win32/Emotet.EC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 73 75 70 70 6c 79 5c 74 72 6f 75 62 6c 65 5c 43 6c 61 73 73 77 68 6f 2e 70 64 62 } //1 c:\supply\trouble\Classwho.pdb
		$a_01_1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 54 00 6f 00 6f 00 77 00 61 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}