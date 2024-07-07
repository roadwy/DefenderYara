
rule Trojan_Win32_Insebro_B{
	meta:
		description = "Trojan:Win32/Insebro.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 03 6a 01 5f 68 90 01 04 ff 75 f8 e8 90 01 02 00 00 59 85 c0 59 74 0d 90 00 } //1
		$a_01_1 = {4e 61 76 69 67 61 74 69 6f 6e 20 62 6c 6f 63 6b 65 64 3c 2f 74 69 74 6c 65 3e } //1 Navigation blocked</title>
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}