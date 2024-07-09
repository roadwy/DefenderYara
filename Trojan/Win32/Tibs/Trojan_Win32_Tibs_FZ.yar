
rule Trojan_Win32_Tibs_FZ{
	meta:
		description = "Trojan:Win32/Tibs.FZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fd ad 48 35 ?? ?? ?? ?? (87|89) 46 04 83 c6 03 e2 f1 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}