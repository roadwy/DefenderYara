
rule Trojan_Win32_Tibs_FG{
	meta:
		description = "Trojan:Win32/Tibs.FG,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3e 00 00 31 d2 b9 09 00 00 00 f7 f1 f7 d8 8d 34 86 56 c3 31 d2 87 d1 5a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}