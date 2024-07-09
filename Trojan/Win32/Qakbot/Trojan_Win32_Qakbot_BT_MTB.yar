
rule Trojan_Win32_Qakbot_BT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 43 8b 45 d8 33 18 89 5d a0 6a 00 e8 [0-04] 8b 5d a0 2b d8 6a 00 e8 [0-04] 2b d8 6a 00 e8 [0-04] 2b d8 8b 45 d8 89 18 6a 00 e8 [0-04] 8b 55 a8 83 c2 04 2b d0 89 55 a8 33 c0 89 45 a4 6a 00 e8 [0-04] 8b 5d d8 83 c3 04 03 5d a4 2b d8 6a 00 e8 [0-04] 2b d8 6a 00 e8 [0-04] 03 d8 89 5d d8 8b 45 a8 3b 45 cc 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}