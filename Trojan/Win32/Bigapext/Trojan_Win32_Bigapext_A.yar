
rule Trojan_Win32_Bigapext_A{
	meta:
		description = "Trojan:Win32/Bigapext.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 f2 bc 88 54 18 ff 43 4e 75 e6 } //1
		$a_01_1 = {67 65 74 78 65 6d 70 6c 32 33 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}