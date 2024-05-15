
rule Virus_Win32_Floxif_EC_MTB{
	meta:
		description = "Virus:Win32/Floxif.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8d 42 04 53 8b c8 8a 5a 02 84 db 74 02 30 19 8a 19 f6 d3 84 db 88 19 74 03 41 eb ea } //00 00 
	condition:
		any of ($a_*)
 
}