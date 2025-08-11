
rule Trojan_Win32_GCleaner_UDP_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.UDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a 2b d0 31 13 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc 72 bc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}