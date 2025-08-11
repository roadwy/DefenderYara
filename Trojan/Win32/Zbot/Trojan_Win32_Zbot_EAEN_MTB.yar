
rule Trojan_Win32_Zbot_EAEN_MTB{
	meta:
		description = "Trojan:Win32/Zbot.EAEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c1 8b 55 fc 8b 45 0c 01 d0 89 ca 88 10 83 45 fc 01 8b 45 fc 3b 45 10 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}