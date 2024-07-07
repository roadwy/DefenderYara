
rule Trojan_Win32_CobaltStrike_GKE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 8b 5d 14 4b 8b 4d 10 33 d2 3b f3 0f 45 d6 8b 75 08 8a 0c 0a 30 0c 30 40 8d 72 01 3b c7 72 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}