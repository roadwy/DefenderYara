
rule Trojan_Win32_Stelpak_AMU_MTB{
	meta:
		description = "Trojan:Win32/Stelpak.AMU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 04 19 85 f6 74 ?? 6a 01 8b ce e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}