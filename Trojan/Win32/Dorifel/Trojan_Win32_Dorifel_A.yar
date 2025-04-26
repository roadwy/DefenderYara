
rule Trojan_Win32_Dorifel_A{
	meta:
		description = "Trojan:Win32/Dorifel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 65 78 65 00 31 31 38 2e 31 30 33 2e 31 32 33 2e 32 32 37 } //1
		$a_01_1 = {45 61 70 48 6f 73 74 00 61 61 61 61 } //1 慅䡰獯t慡慡
		$a_01_2 = {62 62 62 62 2e 64 6c 6c 00 00 4d 65 73 73 65 6e 67 65 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}