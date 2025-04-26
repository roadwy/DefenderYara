
rule TrojanDropper_Win32_Rhadamanthys_EA_MTB{
	meta:
		description = "TrojanDropper:Win32/Rhadamanthys.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 98 48 89 45 98 8d 97 ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 66 89 4d a8 8a 14 1e 88 13 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}