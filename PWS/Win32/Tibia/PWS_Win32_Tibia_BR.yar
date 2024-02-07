
rule PWS_Win32_Tibia_BR{
	meta:
		description = "PWS:Win32/Tibia.BR,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 54 69 62 69 61 43 6c 69 65 6e 74 00 } //01 00 
		$a_01_1 = {61 63 63 6f 75 6e 74 2f 3f 73 75 62 74 6f 70 69 63 3d } //0a 00  account/?subtopic=
		$a_00_2 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e } //01 00  software\microsoft\windows\currentversion\run
		$a_01_3 = {26 6c 6f 67 69 6e 70 61 73 73 77 6f 72 64 3d 00 } //01 00  氦杯湩慰獳潷摲=
		$a_02_4 = {80 3c 2b 43 0f 85 90 01 04 80 7c 2b 01 68 0f 85 90 01 04 80 7c 2b 02 61 0f 85 90 01 04 80 7c 2b 03 72 0f 85 90 01 03 80 7c 2b 04 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}