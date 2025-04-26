
rule Trojan_Win32_Small_P{
	meta:
		description = "Trojan:Win32/Small.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 08 83 c0 01 84 c9 75 f7 8d 7c 24 20 2b c2 83 c7 ff [0-08] 8a 4f 01 83 c7 01 84 c9 75 f6 } //1
		$a_01_1 = {eb 07 8b 08 8b 49 04 03 c8 8b 51 10 81 e2 ff f9 ff ff 53 81 ca 00 08 00 00 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}