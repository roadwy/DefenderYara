
rule Adware_Win32_Scenic{
	meta:
		description = "Adware:Win32/Scenic,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 74 65 6c 6c 2d 61 2d 66 72 69 65 6e 64 2e 68 74 6d } ///tell-a-friend.htm  01 00 
		$a_80_1 = {64 3a 5c 44 65 76 5c 6f 75 74 73 6f 75 72 63 65 5c 4a 6f 69 6e 65 72 45 78 5c 53 6f 75 72 63 65 5c 53 74 61 72 74 65 72 5c 52 65 6c 65 61 73 65 5c 53 74 61 72 74 65 72 2e 70 64 62 } //d:\Dev\outsource\JoinerEx\Source\Starter\Release\Starter.pdb  00 00 
	condition:
		any of ($a_*)
 
}