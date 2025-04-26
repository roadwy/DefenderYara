
rule Trojan_Win32_Cudolkus_A{
	meta:
		description = "Trojan:Win32/Cudolkus.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d f6 03 00 00 76 ?? 57 68 [0-0d] 83 fe 0d 75 } //1
		$a_01_1 = {6b 65 79 73 3a 20 25 73 } //1 keys: %s
		$a_01_2 = {77 69 6e 6b 2e 6c 6f 67 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}