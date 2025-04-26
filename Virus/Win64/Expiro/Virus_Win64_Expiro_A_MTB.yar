
rule Virus_Win64_Expiro_A_MTB{
	meta:
		description = "Virus:Win64/Expiro.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b ec 48 83 ec 20 48 83 e4 f0 48 8d ?? ?? ?? ?? ?? 48 be 00 00 00 00 00 00 00 00 52 81 aa f0 03 00 00 ?? ?? ?? ?? 81 b2 a8 00 00 00 ?? ?? ?? ?? 81 6a 2c ?? ?? ?? ?? f7 92 9c 01 00 00 81 aa fc 00 00 00 ?? ?? ?? ?? 81 b2 38 03 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}