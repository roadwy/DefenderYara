
rule Trojan_Win32_Glupteba_EAUP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EAUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ec 56 8b 31 8b 4d 08 8a 04 0a 88 04 31 5e 5d } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}