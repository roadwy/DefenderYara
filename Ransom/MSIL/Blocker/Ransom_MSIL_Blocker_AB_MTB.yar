
rule Ransom_MSIL_Blocker_AB_MTB{
	meta:
		description = "Ransom:MSIL/Blocker.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 2b f8 02 20 93 47 9a 75 28 ?? ?? ?? 06 06 73 1f 00 00 0a 06 6f ?? ?? ?? 0a 17 59 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 20 f8 47 9a 75 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 1b 2d 08 26 26 07 17 58 0b 2b 07 28 ?? ?? ?? 06 2b f3 07 1f 14 32 b7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}