
rule Trojan_Win32_Redline_PCG_MTB{
	meta:
		description = "Trojan:Win32/Redline.PCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8d 4c 24 30 89 54 24 30 8b 54 24 3c e8 ?? ?? ?? ?? 8b 44 24 30 33 44 24 28 89 35 ?? ?? ?? ?? 31 44 24 10 8b 44 24 10 29 44 24 18 8b 44 24 40 29 44 24 14 4b 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}