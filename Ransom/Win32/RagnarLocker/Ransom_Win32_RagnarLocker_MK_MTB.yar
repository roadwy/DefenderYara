
rule Ransom_Win32_RagnarLocker_MK_MTB{
	meta:
		description = "Ransom:Win32/RagnarLocker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 41 47 4e 52 50 57 } //RAGNRPW  01 00 
		$a_80_1 = {5c 5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 25 64 } //\\.\PHYSICALDRIVE%d  01 00 
		$a_80_2 = {21 24 52 34 47 4e 34 52 } //!$R4GN4R  01 00 
		$a_80_3 = {24 21 2e 74 78 74 } //$!.txt  01 00 
		$a_80_4 = {2d 2d 2d 45 4e 44 20 4b 45 59 } //---END KEY  01 00 
		$a_80_5 = {2d 2d 2d 42 45 47 49 4e 20 4b 45 59 } //---BEGIN KEY  01 00 
		$a_80_6 = {2e 72 61 67 6e 40 72 } //.ragn@r  00 00 
		$a_00_7 = {5d 04 00 00 83 } //3b 04 
	condition:
		any of ($a_*)
 
}