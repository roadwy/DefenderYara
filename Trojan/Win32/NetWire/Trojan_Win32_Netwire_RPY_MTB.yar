
rule Trojan_Win32_Netwire_RPY_MTB{
	meta:
		description = "Trojan:Win32/Netwire.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c0 31 c2 8b 45 ec 83 c0 0c 8b 00 31 d0 89 45 f0 8b 45 fc c1 e8 18 89 c2 8b 45 10 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}