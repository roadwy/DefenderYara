
rule Trojan_Win32_Vundo_BI{
	meta:
		description = "Trojan:Win32/Vundo.BI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 a4 27 92 7f aa 83 48 9c 51 18 06 83 fa 3e 74 0f 0a 75 3b 7a 0e 3b c1 2c 01 c8 75 ec 33 c0 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}