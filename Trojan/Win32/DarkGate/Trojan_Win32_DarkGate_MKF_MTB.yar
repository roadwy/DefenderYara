
rule Trojan_Win32_DarkGate_MKF_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 8b 4c 24 20 66 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? ff 44 24 3c 0f b7 0c 41 0f b7 04 5f 2b c8 8b 44 24 38 31 88 30 78 00 00 8b 44 24 10 0f b7 35 ?? ?? ?? ?? 0f b7 08 a1 ?? ?? ?? ?? 3b 34 88 7d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}