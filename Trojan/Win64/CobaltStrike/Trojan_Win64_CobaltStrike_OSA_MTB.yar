
rule Trojan_Win64_CobaltStrike_OSA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 88 57 fc 88 54 24 72 0f b6 54 24 73 41 32 51 0d 41 88 57 fd 88 54 24 73 0f b6 54 24 74 41 32 51 0e 41 88 57 fe 45 32 71 0f 4c 39 8c 24 ?? ?? ?? ?? 88 54 24 50 45 88 77 ff 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}