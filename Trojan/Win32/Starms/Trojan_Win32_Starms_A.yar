
rule Trojan_Win32_Starms_A{
	meta:
		description = "Trojan:Win32/Starms.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 } //1 SOFTWARE\MSoftware
		$a_01_1 = {5c 00 6d 00 73 00 66 00 74 00 6c 00 64 00 72 00 2e 00 64 00 6c 00 6c 00 2c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //1 \msftldr.dll,Install
		$a_01_2 = {5c 00 6d 00 73 00 66 00 74 00 64 00 6d 00 2e 00 65 00 78 00 65 00 00 00 5c 00 6d 00 73 00 66 00 74 00 64 00 6d 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}