
rule Trojan_Win32_Wasalad_A{
	meta:
		description = "Trojan:Win32/Wasalad.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 62 61 63 6b 77 61 72 64 5c 69 6e 63 68 5c 65 6e 75 6d 65 72 61 74 69 6f 6e 5c 41 74 6d 65 6c 5c 6e 65 63 65 73 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}