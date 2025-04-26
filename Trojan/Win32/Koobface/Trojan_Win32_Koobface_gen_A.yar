
rule Trojan_Win32_Koobface_gen_A{
	meta:
		description = "Trojan:Win32/Koobface.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 85 38 fe ff ff 68 00 01 00 00 50 ff 75 fc } //2
		$a_01_1 = {74 6f 70 65 6e 69 6e 67 20 37 } //1 topening 7
		$a_01_2 = {53 54 25 73 72 72 65 } //1 ST%srre
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}