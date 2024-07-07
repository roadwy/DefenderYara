
rule Trojan_Win32_Glupteba_GA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 1e 46 3b f7 90 13 90 02 10 81 ff 69 04 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}