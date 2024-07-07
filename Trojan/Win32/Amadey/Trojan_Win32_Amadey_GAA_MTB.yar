
rule Trojan_Win32_Amadey_GAA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2a 51 04 1c 81 84 24 90 01 04 d4 5f bb 25 b8 90 01 04 f7 a4 24 90 01 04 8b 84 24 90 01 04 81 84 24 90 01 04 07 82 f9 48 81 ac 24 90 01 04 18 2b 67 55 81 84 24 90 01 04 40 86 92 69 81 ac 24 90 01 04 ac b7 aa 67 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}