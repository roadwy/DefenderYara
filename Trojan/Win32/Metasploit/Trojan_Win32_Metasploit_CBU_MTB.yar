
rule Trojan_Win32_Metasploit_CBU_MTB{
	meta:
		description = "Trojan:Win32/Metasploit.CBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d4 01 d0 0f b6 00 31 c1 89 ca 8d 8d 97 fb ff ff 8b 45 d0 01 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}