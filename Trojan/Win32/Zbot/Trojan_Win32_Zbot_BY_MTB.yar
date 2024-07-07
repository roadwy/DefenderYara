
rule Trojan_Win32_Zbot_BY_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 16 00 da f6 d0 88 d0 f6 d0 aa 83 c6 04 83 c7 03 ba 30 00 00 00 83 e9 04 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}