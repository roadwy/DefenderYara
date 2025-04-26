
rule Trojan_Win32_Straba_RO_MTB{
	meta:
		description = "Trojan:Win32/Straba.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 75 e8 8a 1c 06 0f b6 fb 01 cf 89 45 dc 31 c9 89 55 d8 89 ca 8b 4d f0 f7 f1 8b 4d ec 0f b6 14 11 01 d7 89 f8 99 8b 7d d8 f7 ff 8a 3c 16 8b 4d dc 88 3c 0e 88 1c 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}