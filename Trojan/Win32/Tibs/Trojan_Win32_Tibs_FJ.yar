
rule Trojan_Win32_Tibs_FJ{
	meta:
		description = "Trojan:Win32/Tibs.FJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 ca 83 c4 ?? 83 ec ?? 6a ?? ff 15 ?? ?? ?? ?? (69 c0 00 ?? ?? 00 ba|00 00 01 00 f7 e2 )} //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}