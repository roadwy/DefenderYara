
rule TrojanSpy_Win32_Plimrost_D_bit{
	meta:
		description = "TrojanSpy:Win32/Plimrost.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 4d 6f 64 75 6c 65 3e 7b 32 37 36 44 32 33 39 34 2d 30 31 35 35 2d 34 43 31 34 2d 42 41 43 46 2d 31 31 38 39 32 34 35 30 37 33 44 39 7d } //01 00 
		$a_01_1 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e } //00 00 
	condition:
		any of ($a_*)
 
}