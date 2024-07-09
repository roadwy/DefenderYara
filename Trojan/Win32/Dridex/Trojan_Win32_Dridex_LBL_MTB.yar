
rule Trojan_Win32_Dridex_LBL_MTB{
	meta:
		description = "Trojan:Win32/Dridex.LBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 ?? 89 4d ?? 2b 4d ?? 31 d9 83 e0 00 09 c8 8b 4d ?? 81 e1 [0-04] 8b 0c e4 83 ec ?? aa 49 75 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}