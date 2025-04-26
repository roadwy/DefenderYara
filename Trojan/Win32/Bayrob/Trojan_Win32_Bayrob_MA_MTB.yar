
rule Trojan_Win32_Bayrob_MA_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {84 c0 75 04 32 c0 5d c3 e8 1e ef 02 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}