
rule Trojan_Win32_Qakbot_PS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 14 31 8b 0d [0-04] 33 15 [0-04] 89 14 0e 83 c6 04 8b 0d [0-04] 81 c1 [0-04] 0f af 48 ?? 89 48 ?? 8b 0d [0-06] 88 [0-04] 8b 0d [0-04] 8b 49 [0-04] 2b 0d [0-04] 83 e9 [0-04] 0f af 88 [0-04] 89 88 [0-04] 8b 0d [0-04] 81 f1 [0-04] 29 88 [0-04] 81 fe [0-04] 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}