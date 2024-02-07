
rule Trojan_Win32_Chinoxy_B_bit{
	meta:
		description = "Trojan:Win32/Chinoxy.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 46 20 2f 49 4d 90 02 30 2e 65 78 65 90 00 } //01 00 
		$a_01_1 = {72 65 67 20 61 64 64 20 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 } //01 00  reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
		$a_01_2 = {40 53 45 54 20 53 4c 45 45 50 3d 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e } //01 00  @SET SLEEP=ping 127.0.0.1 -n
		$a_01_3 = {40 64 65 6c 20 66 73 65 77 65 77 66 72 74 72 65 74 72 77 77 65 2e 65 77 65 } //01 00  @del fsewewfrtretrwwe.ewe
		$a_01_4 = {40 65 63 68 6f 20 6b 6a 79 75 79 75 74 75 79 74 6e 66 67 66 68 67 68 64 3e 3e 66 73 65 77 65 77 66 72 74 72 65 74 72 77 77 65 2e 65 77 65 } //00 00  @echo kjyuyutuytnfgfhghd>>fsewewfrtretrwwe.ewe
	condition:
		any of ($a_*)
 
}