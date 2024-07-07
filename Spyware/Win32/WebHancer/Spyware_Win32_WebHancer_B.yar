
rule Spyware_Win32_WebHancer_B{
	meta:
		description = "Spyware:Win32/WebHancer.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 77 65 62 48 61 6e 63 65 72 } //3 Software\webHancer
		$a_01_1 = {42 38 34 45 37 33 31 42 2d 44 32 45 44 2d 34 65 38 32 2d 38 31 38 32 2d 41 35 32 46 44 34 37 31 34 32 38 34 } //3 B84E731B-D2ED-4e82-8182-A52FD4714284
		$a_01_2 = {43 43 46 32 33 39 35 35 2d 43 35 45 43 2d 34 65 63 61 2d 39 31 36 36 2d 35 33 44 43 32 32 43 31 44 42 43 39 } //3 CCF23955-C5EC-4eca-9166-53DC22C1DBC9
		$a_01_3 = {77 68 69 65 68 6c 70 72 2e 64 6c 6c } //3 whiehlpr.dll
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=12
 
}