
rule TrojanProxy_Win32_Chopanez_gen_A{
	meta:
		description = "TrojanProxy:Win32/Chopanez.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 05 00 "
		
	strings :
		$a_03_0 = {74 65 55 8b 2d 90 01 02 40 00 8b ff 8d 54 24 14 52 68 00 28 00 00 8d 44 24 30 50 53 c7 44 24 24 00 28 00 00 ff 15 90 01 02 40 00 85 c0 74 34 8b 44 24 14 85 c0 74 31 90 00 } //01 00 
		$a_01_1 = {47 25 79 25 6d 25 64 25 48 25 4d 25 53 2e 25 2e 20 25 70 20 25 45 20 25 55 20 25 43 3a 25 63 20 25 52 3a 25 72 20 25 4f 20 25 49 20 25 68 20 25 54 } //01 00  G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T
		$a_01_2 = {41 63 63 65 70 74 69 6e 67 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 20 5b 25 75 2f 25 75 5d } //01 00  Accepting connections [%u/%u]
		$a_01_3 = {3a 54 43 50 3a 2a 3a 45 6e 61 62 6c 65 64 3a 4d 69 63 72 6f 73 6f 66 74 20 73 74 61 6e 64 61 72 64 20 70 72 6f 74 65 63 74 6f 72 } //01 00  :TCP:*:Enabled:Microsoft standard protector
		$a_01_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 47 6c 6f 62 61 6c 6c 79 4f 70 65 6e 50 6f 72 74 73 5c 4c 69 73 74 } //00 00  SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\GloballyOpenPorts\List
	condition:
		any of ($a_*)
 
}