
rule Trojan_Win32_Qbot_NA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a c3 2c 09 02 c2 90 18 0f 90 02 02 8b 90 01 01 2b 90 01 01 0f 90 02 02 2b 90 01 01 89 90 02 03 8b 90 02 03 89 90 02 05 8b 90 02 03 8a e2 80 ec 09 8b 3f 02 e0 3b ce 90 18 8a ca 81 90 02 05 2a cb 89 90 02 05 80 90 02 02 02 c1 8b 90 02 03 83 90 02 04 89 39 8b 90 02 05 8b 90 02 04 69 90 02 05 83 90 02 04 0f 90 02 02 89 90 02 03 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}