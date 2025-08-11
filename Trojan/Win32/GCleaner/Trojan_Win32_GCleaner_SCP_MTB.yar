
rule Trojan_Win32_GCleaner_SCP_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.SCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 50 0a 00 00 10 00 00 00 7a 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 40 69 3c 00 00 60 0a 00 00 60 27 00 00 8a 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}