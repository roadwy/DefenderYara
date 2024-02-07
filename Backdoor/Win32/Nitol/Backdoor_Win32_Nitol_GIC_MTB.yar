
rule Backdoor_Win32_Nitol_GIC_MTB{
	meta:
		description = "Backdoor:Win32/Nitol.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {50 8d 45 dc c7 45 90 01 01 4b 45 52 4e 50 c7 45 90 01 01 45 4c 33 32 c7 45 90 01 01 2e 64 6c 6c c6 45 90 01 01 00 c7 45 90 01 01 4c 6f 61 64 c7 45 90 01 01 4c 69 62 72 c7 45 90 01 01 61 72 79 41 c6 45 90 01 01 00 ff 15 90 00 } //01 00 
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 31 36 35 31 32 5c 44 65 73 6b 74 6f 70 5c 79 6b } //00 00  C:\Users\16512\Desktop\yk
	condition:
		any of ($a_*)
 
}