
rule Trojan_Win32_Qakbot_BW_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 33 05 [0-04] a3 [0-04] 6a 00 e8 [0-04] 8b 1d [0-04] 2b d8 6a 00 e8 [0-04] 2b d8 6a 00 e8 [0-04] 2b d8 a1 [0-04] 89 18 a1 [0-04] 83 c0 04 a3 [0-04] 33 c0 a3 [0-04] 6a 00 e8 [0-04] 8b 15 [0-04] 83 c2 04 03 15 [0-04] 03 c2 40 a3 [0-04] a1 [0-04] 3b 05 [0-04] 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}