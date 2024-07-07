
rule Trojan_Win32_Stealer_RPH_MTB{
	meta:
		description = "Trojan:Win32/Stealer.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 6a 40 ff 75 e4 ff 75 d8 e8 90 01 04 33 c0 89 45 d0 8b 55 d0 3b 55 e4 7f 1d 8b 4d d8 03 4d d0 89 4d cc 8b 45 cc 8b 55 dc 31 10 83 45 d0 04 8b 4d d0 3b 4d e4 7e e3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}