
rule Trojan_Win32_Stealerc_GME_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d4 cc c8 de 66 c7 84 24 ?? ?? ?? ?? c9 c8 8a 84 0c ?? ?? ?? ?? 34 bb 88 44 0c ?? 41 83 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}