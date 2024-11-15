
rule Trojan_Win32_Bayrob_MN_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MN!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b f0 33 ff 39 3e 74 1a 56 e8 c8 04 00 00 59 84 c0 74 0f 57 6a 02 57 8b 36 8b ce } //1
		$a_01_1 = {4d 61 69 6e 20 49 6e 76 6f 6b 65 64 } //1 Main Invoked
		$a_01_2 = {72 65 67 65 78 } //1 regex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}