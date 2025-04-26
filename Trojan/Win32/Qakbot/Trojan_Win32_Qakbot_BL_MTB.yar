
rule Trojan_Win32_Qakbot_BL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 6a 00 e8 [0-04] 2b d8 a1 [0-04] 33 18 89 1d [0-04] 6a 00 e8 [0-04] 6a 00 e8 [0-04] 6a 00 e8 [0-04] 6a 00 e8 [0-04] 6a 00 e8 [0-04] a1 [0-04] 8b 15 [0-04] 89 02 a1 [0-04] 83 c0 04 a3 [0-04] 33 c0 a3 [0-04] a1 [0-04] 83 c0 04 03 05 [0-04] a3 [0-04] a1 [0-04] 3b 05 [0-04] 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}