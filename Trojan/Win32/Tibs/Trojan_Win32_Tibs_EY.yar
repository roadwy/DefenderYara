
rule Trojan_Win32_Tibs_EY{
	meta:
		description = "Trojan:Win32/Tibs.EY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 ce 83 c9 ff 41 81 c1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 8d 16 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}