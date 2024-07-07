
rule Trojan_Win32_Doina_GHJ_MTB{
	meta:
		description = "Trojan:Win32/Doina.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 cc 83 c0 01 89 45 cc 8b 4d cc 3b 4d d0 7d 90 01 01 8b 55 cc 52 8d 4d d4 e8 90 01 04 0f be 18 83 f3 90 01 01 8b 45 cc 50 8d 4d d4 e8 90 01 04 88 18 90 00 } //10
		$a_01_1 = {61 70 69 2e 6a 77 68 73 73 2e 63 6f 6d } //1 api.jwhss.com
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}