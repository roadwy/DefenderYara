
rule Trojan_Win32_Dridex_GN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 cf 36 ea 2e 5d [0-06] 0f b6 fc 29 f9 88 cc 88 65 ?? 8b 4d ?? 8b 7d ?? 8a 65 ?? 88 24 0f 88 45 ?? 89 75 ?? 89 55 ?? 83 c4 18 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}