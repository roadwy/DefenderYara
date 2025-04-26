
rule Trojan_Win32_Qakbot_CF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 03 05 [0-04] 48 a3 [0-04] 6a 00 e8 [0-04] 8b d8 a1 [0-04] 8b 00 03 45 f8 03 d8 6a 00 e8 [0-04] 03 d8 a1 [0-04] 89 18 a1 [0-04] 03 05 [0-04] a3 [0-04] a1 [0-04] 8b 00 33 05 [0-04] a3 [0-04] a1 [0-04] 8b 15 [0-04] 89 10 8b 45 f8 83 c0 04 89 45 f8 33 c0 a3 [0-04] a1 [0-04] 83 c0 04 03 05 [0-04] a3 [0-04] 8b 45 f8 3b 05 [0-04] 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}