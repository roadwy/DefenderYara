
rule Adware_Win32_Trickler_A_MTB{
	meta:
		description = "Adware:Win32/Trickler.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 03 32 06 46 4f 75 0a be 90 01 04 bf 90 01 04 88 03 83 f9 00 74 04 4b 49 eb e3 90 00 } //01 00 
		$a_00_1 = {74 72 69 63 6b 6c 65 2e 67 61 74 6f 72 2e 63 6f 6d } //00 00  trickle.gator.com
	condition:
		any of ($a_*)
 
}