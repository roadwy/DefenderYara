
rule Trojan_Win32_Tibs_FD{
	meta:
		description = "Trojan:Win32/Tibs.FD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c5 83 ed ?? 83 ed ?? 66 09 ed [0-01] 74 05 05 00 02 00 00 89 ea 09 ea [0-01] 75 ?? bf } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}