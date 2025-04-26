
rule Trojan_Win32_Qakbot_AU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fc ff 03 05 [0-04] 8b 15 [0-04] 33 02 a3 [0-04] a1 [0-04] 8b 15 [0-04] 89 02 a1 [0-04] 83 c0 04 a3 [0-04] 33 c0 a3 [0-04] a1 [0-04] 83 c0 04 03 05 [0-04] a3 [0-04] a1 [0-04] 3b 05 [0-04] 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}