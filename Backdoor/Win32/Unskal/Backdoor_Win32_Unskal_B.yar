
rule Backdoor_Win32_Unskal_B{
	meta:
		description = "Backdoor:Win32/Unskal.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {b0 20 2a c2 32 c3 42 88 04 0e 41 8a 19 84 db 75 } //01 00 
		$a_01_1 = {7b 38 38 45 42 33 37 32 35 2d 46 39 37 45 2d 34 43 33 37 2d 39 43 45 38 2d 30 41 39 32 38 41 32 30 33 32 30 43 7d } //01 00  {88EB3725-F97E-4C37-9CE8-0A928A20320C}
		$a_01_2 = {5c 77 69 6e 73 65 72 76 73 2e 65 78 65 } //01 00  \winservs.exe
		$a_01_3 = {5c 4f 72 61 63 6c 65 4a 61 76 61 5c 6a 61 76 61 77 2e 65 78 65 } //01 00  \OracleJava\javaw.exe
		$a_01_4 = {5c 6e 73 73 6b 72 6e 6c 00 } //00 00 
		$a_00_5 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}