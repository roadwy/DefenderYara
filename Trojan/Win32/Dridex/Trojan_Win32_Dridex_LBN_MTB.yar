
rule Trojan_Win32_Dridex_LBN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.LBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 f3 89 75 ?? 33 75 ?? 09 de 83 e0 00 09 f0 8b 75 ?? 8f 45 ?? 8b 4d ?? aa 49 75 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}