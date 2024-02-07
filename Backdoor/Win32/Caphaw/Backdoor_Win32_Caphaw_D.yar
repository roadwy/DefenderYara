
rule Backdoor_Win32_Caphaw_D{
	meta:
		description = "Backdoor:Win32/Caphaw.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {62 6f 74 6e 65 74 3d 25 73 } //02 00  botnet=%s
		$a_01_1 = {63 6f 6d 6d 61 6e 64 73 20 65 78 65 63 20 73 74 61 74 75 73 3d 25 73 } //01 00  commands exec status=%s
		$a_01_2 = {25 73 25 73 25 69 2e 64 61 74 } //00 00  %s%s%i.dat
		$a_00_3 = {80 10 00 } //00 57 
	condition:
		any of ($a_*)
 
}