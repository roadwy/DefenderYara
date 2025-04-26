
rule Backdoor_BAT_Remcos_MB_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 18 5b 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 04 18 58 13 04 11 04 08 32 df 09 13 05 de 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}