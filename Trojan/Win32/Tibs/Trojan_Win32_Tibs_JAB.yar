
rule Trojan_Win32_Tibs_JAB{
	meta:
		description = "Trojan:Win32/Tibs.JAB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 d3 01 00 00 e8 89 01 00 00 e8 58 02 00 00 b8 00 00 00 00 85 c0 75 27 ff 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}