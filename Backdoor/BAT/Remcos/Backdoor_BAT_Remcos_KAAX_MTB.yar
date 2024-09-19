
rule Backdoor_BAT_Remcos_KAAX_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.KAAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 58 08 5d 13 ?? 06 7b ?? 00 00 04 11 ?? 91 11 ?? 61 11 ?? 59 20 00 02 00 00 58 13 ?? 11 ?? 20 00 01 00 00 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}