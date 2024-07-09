
rule Trojan_Win32_Glupteba_OJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 08 8b e5 5d c3 90 09 2d 00 a1 ?? ?? ?? ?? ?? ?? 89 [0-02] 31 [0-02] c7 05 [0-0a] 8b [0-02] 01 [0-05] a1 [0-04] 8b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}