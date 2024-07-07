
rule TrojanClicker_Win32_VB_DN{
	meta:
		description = "TrojanClicker:Win32/VB.DN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 58 4e 6c 63 6c 39 77 63 6d 56 6d 4b 43 4a 75 5a 58 52 33 62 33 4a 72 4c 6e 42 79 62 33 68 35 4c 6e 4e 76 59 32 74 7a 58 33 42 76 63 6e 51 69 4c 43 41 34 4d 43 6b } //1 dXNlcl9wcmVmKCJuZXR3b3JrLnByb3h5LnNvY2tzX3BvcnQiLCA4MCk
		$a_01_1 = {56 00 47 00 56 00 79 00 63 00 6d 00 45 00 3d 00 } //1 VGVycmE=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}