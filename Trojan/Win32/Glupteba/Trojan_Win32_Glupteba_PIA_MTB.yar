
rule Trojan_Win32_Glupteba_PIA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 2c 01 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? d3 ea 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 28 e8 ?? ?? ?? ?? 8b 44 24 20 31 44 24 10 81 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}