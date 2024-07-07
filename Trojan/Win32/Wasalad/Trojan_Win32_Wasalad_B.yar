
rule Trojan_Win32_Wasalad_B{
	meta:
		description = "Trojan:Win32/Wasalad.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 70 6f 73 74 6d 61 73 74 65 72 5c 6d 65 72 67 65 5c 50 65 61 73 61 6e 74 73 5c 42 69 6c 6c 79 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}