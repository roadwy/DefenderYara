
rule Trojan_Win32_Asruex_A{
	meta:
		description = "Trojan:Win32/Asruex.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 44 00 00 00 8d 44 24 20 88 18 40 83 e9 01 75 f8 c7 44 24 20 44 00 00 00 b9 10 00 00 00 8d 44 24 10 8d 49 00 88 18 40 83 e9 01 75 f8 8b 0d 28 54 4d 00 8b 11 52 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}