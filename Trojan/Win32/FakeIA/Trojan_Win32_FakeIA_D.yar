
rule Trojan_Win32_FakeIA_D{
	meta:
		description = "Trojan:Win32/FakeIA.D,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 6e 61 62 6c 65 20 50 72 6f 74 65 63 74 69 6f 6e 00 00 00 42 55 54 54 4f 4e 00 00 55 6e 62 6c 6f 63 6b 00 4b 65 65 70 20 42 6c 6f 63 6b 69 6e 67 00 00 00 43 6c 69 63 6b 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 61 63 74 69 76 61 74 65 20 70 72 6f 74 65 63 74 69 6f 6e 2e 00 00 53 54 41 54 49 43 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}