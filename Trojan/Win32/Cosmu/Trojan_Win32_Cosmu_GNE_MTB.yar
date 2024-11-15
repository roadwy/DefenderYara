
rule Trojan_Win32_Cosmu_GNE_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 74 ea 2a 00 db 33 34 3a b1 94 ?? ?? 97 d2 60 13 f2 14 ?? 2a 2e } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}