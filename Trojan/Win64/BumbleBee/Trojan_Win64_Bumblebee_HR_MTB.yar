
rule Trojan_Win64_Bumblebee_HR_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.HR!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b 0c 00 33 8a 94 00 00 00 48 8b 82 c0 00 00 00 41 89 0c 00 } //00 00 
	condition:
		any of ($a_*)
 
}