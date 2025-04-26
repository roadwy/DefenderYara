
rule Virus_Win32_Floxif_RPX_MTB{
	meta:
		description = "Virus:Win32/Floxif.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 51 02 33 c2 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 33 c0 8a 02 f7 d0 8b 4d 08 } //1
		$a_03_1 = {55 8b ec b8 01 00 00 00 85 c0 74 0d 68 60 ea 00 00 ff 15 ?? ?? ?? ?? eb ea 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}