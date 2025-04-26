
rule Trojan_Win32_Hupigon_AA_MTB{
	meta:
		description = "Trojan:Win32/Hupigon.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {10 8b 84 24 ?? 01 00 00 73 07 8d 84 24 ?? 01 00 00 8a ?? 38 8b 44 24 ?? 30 ?? 06 8b ?? 24 ?? 83 c6 01 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}