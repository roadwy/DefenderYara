
rule Trojan_Win32_Tibs_HH{
	meta:
		description = "Trojan:Win32/Tibs.HH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {87 02 83 ea fd 42 83 c1 fe 83 e9 02 85 c9 90 09 10 00 [0-03] 68 ?? ?? 00 00 59 87 02 [0-03] 35 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}