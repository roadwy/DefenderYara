
rule Trojan_Win32_Tibs_GF{
	meta:
		description = "Trojan:Win32/Tibs.GF,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 00 66 ad 69 c0 00 00 01 00 66 ad c1 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}