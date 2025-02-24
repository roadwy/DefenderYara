
rule Trojan_Win32_Glupteba_EAH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f3 33 f7 29 75 f8 8b 45 dc 29 45 fc 83 6d f0 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}