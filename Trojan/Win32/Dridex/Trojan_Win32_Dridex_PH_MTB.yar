
rule Trojan_Win32_Dridex_PH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 ?? ff [0-04] 6a 00 89 [0-02] 29 ?? 09 ?? 89 ?? 5d 81 ?? ?? ?? ?? ?? 8f ?? ?? 03 ?? ?? aa 49 75 } //1
		$a_02_1 = {d3 c0 8a fc 8a e6 d3 cb ff [0-04] 89 [0-02] 33 [0-04] 83 [0-04] 8b [0-02] 8f [0-02] 8b [0-02] aa 49 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}