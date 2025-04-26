
rule Trojan_Win32_Glupteba_EAHH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EAHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 05 03 f2 89 45 fc 8b 45 f4 01 45 fc 8b 5d f8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}