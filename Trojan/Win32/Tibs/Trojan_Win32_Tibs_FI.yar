
rule Trojan_Win32_Tibs_FI{
	meta:
		description = "Trojan:Win32/Tibs.FI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {87 ca 83 c4 ?? 83 c4 ?? 8d 1d ?? ?? 40 00 [0-02] 6a ?? ff (13|d3) 69 c0 00 00 01 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}