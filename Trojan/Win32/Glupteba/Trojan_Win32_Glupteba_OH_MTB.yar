
rule Trojan_Win32_Glupteba_OH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.OH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 39 83 [0-02] 90 18 47 3b ?? 90 18 81 [0-05] 90 18 8b [0-05] e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}