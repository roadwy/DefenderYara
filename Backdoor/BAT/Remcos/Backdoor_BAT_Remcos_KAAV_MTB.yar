
rule Backdoor_BAT_Remcos_KAAV_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.KAAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 13 ?? 11 ?? 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 11 ?? 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}