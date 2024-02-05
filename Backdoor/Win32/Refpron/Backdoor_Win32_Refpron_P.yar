
rule Backdoor_Win32_Refpron_P{
	meta:
		description = "Backdoor:Win32/Refpron.P,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {6d ce 00 00 90 02 20 66 81 45 90 01 01 bf 58 90 00 } //01 00 
		$a_01_1 = {62 66 6b 71 2e 63 6f 6d 7c } //01 00 
		$a_01_2 = {7c 6a 73 61 63 74 69 76 69 74 79 2e 63 6f 6d } //01 00 
		$a_01_3 = {4e 65 65 64 4b 69 6c 6c 00 } //01 00 
		$a_01_4 = {6e 72 6e 64 66 6f 72 63 74 72 31 00 } //01 00 
		$a_01_5 = {5c 53 79 73 74 65 6d 45 78 63 6c 61 6d 61 74 69 6f 6e 5c 2e 43 75 72 72 65 6e 74 00 } //01 00 
		$a_01_6 = {64 69 73 63 6f 76 65 72 2e 65 78 65 3d 00 } //01 00 
		$a_01_7 = {6d 00 00 00 ff ff ff ff 01 00 00 00 73 00 00 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 01 00 00 00 62 00 00 00 ff ff ff ff 01 00 00 00 69 00 00 00 ff ff ff ff 01 00 00 00 6e } //00 00 
	condition:
		any of ($a_*)
 
}