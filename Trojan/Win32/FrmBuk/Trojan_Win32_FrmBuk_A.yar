
rule Trojan_Win32_FrmBuk_A{
	meta:
		description = "Trojan:Win32/FrmBuk.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 f9 86 5d 00 00 75 c0 90 90 8b c6 90 90 90 ba 51 1a 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}