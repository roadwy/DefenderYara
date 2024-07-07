
rule Trojan_Win32_Cridex_KPS_MTB{
	meta:
		description = "Trojan:Win32/Cridex.KPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f be 04 16 8a cb 8a d0 f6 d1 f6 d2 0a ca 0a d8 22 cb 88 0c 2e 46 3b 74 24 2c 0f 82 } //2
		$a_02_1 = {03 ca 81 e1 ff 00 00 00 0f b6 14 8d 90 01 04 a3 90 01 04 30 14 33 83 ee 01 79 90 09 07 00 8b 0c 85 90 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}