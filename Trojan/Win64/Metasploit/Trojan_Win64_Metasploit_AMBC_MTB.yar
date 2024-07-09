
rule Trojan_Win64_Metasploit_AMBC_MTB{
	meta:
		description = "Trojan:Win64/Metasploit.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 10 44 31 c0 89 c1 8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10 83 45 fc 01 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}