
rule Trojan_Win32_Tibs_GV{
	meta:
		description = "Trojan:Win32/Tibs.GV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d6 52 ac 86 (c4|e0) ac 86 (c4|e0) c1 (|) e0 e8 ?? c1 (|) e0 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}