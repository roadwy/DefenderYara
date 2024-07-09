
rule Trojan_Win32_RisePro_GPB_MTB{
	meta:
		description = "Trojan:Win32/RisePro.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 01 8d 48 ?? 30 4c 05 ?? 40 83 f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}