
rule Worm_Win32_Ambler_B{
	meta:
		description = "Worm:Win32/Ambler.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {24 f8 50 56 ff 15 90 01 04 56 ff 15 90 09 0c 00 be 90 01 04 56 ff 15 90 00 } //1
		$a_03_1 = {6a 01 5f 8d 4b 01 2b fb 0f be 51 ff 8a c2 03 75 fc f6 d0 32 c2 24 90 01 01 f6 d2 32 c2 88 41 ff 90 00 } //1
		$a_00_2 = {5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 49 6e 73 74 61 6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c } //1 \Active Setup\Installed Components\
		$a_00_3 = {2a 2a 2a 47 52 41 42 42 45 44 20 42 41 4c 41 4e 43 45 2a 2a 2a 2a } //1 ***GRABBED BALANCE****
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}