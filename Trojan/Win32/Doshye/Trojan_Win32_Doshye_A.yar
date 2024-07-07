
rule Trojan_Win32_Doshye_A{
	meta:
		description = "Trojan:Win32/Doshye.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 44 62 69 6e 21 4e 67 67 0c 0b 73 64 66 64 65 68 75 21 2e 72 21 24 56 48 4f 45 48 53 24 5d 72 78 72 75 64 6c 5d 72 77 62 69 64 72 75 2f 73 64 66 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}