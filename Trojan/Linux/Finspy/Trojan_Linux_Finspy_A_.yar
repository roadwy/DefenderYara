
rule Trojan_Linux_Finspy_A_{
	meta:
		description = "Trojan:Linux/Finspy.A!!Finspy.A,SIGNATURE_TYPE_ARHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {a5 aa ca a6 54 5a 90 01 02 5a a5 0a 90 00 } //01 00 
		$a_01_1 = {7f 0d 45 4c 46 01 02 c2 14 68 03 05 0e } //01 00 
		$a_01_2 = {7f 07 45 4c 46 02 01 1e 15 01 8e 03 0e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Linux_Finspy_A__2{
	meta:
		description = "Trojan:Linux/Finspy.A!!Finspy.A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {25 73 2f 2e 6b 64 65 2f 41 75 74 6f 73 74 61 72 74 } //01 00  %s/.kde/Autostart
		$a_00_1 = {25 73 2f 2e 6b 64 65 34 2f 41 75 74 6f 73 74 61 72 74 } //01 00  %s/.kde4/Autostart
		$a_00_2 = {25 73 2f 2e 62 61 73 68 5f 70 72 6f 66 69 6c 65 } //01 00  %s/.bash_profile
		$a_00_3 = {67 5f 70 69 6e 73 74 61 6c 6c 5f 68 6f 73 74 5f 6c 6f 63 61 74 69 6f 6e } //01 00  g_pinstall_host_location
		$a_00_4 = {67 5f 70 6c 61 75 6e 63 68 65 72 } //01 00  g_plauncher
		$a_00_5 = {68 79 70 65 72 76 69 73 6f 72 20 64 65 74 65 63 74 65 64 } //00 00  hypervisor detected
	condition:
		any of ($a_*)
 
}
rule Trojan_Linux_Finspy_A__3{
	meta:
		description = "Trojan:Linux/Finspy.A!!Finspy.A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 73 20 61 75 78 77 77 20 7c 20 67 72 65 70 20 2d 69 45 65 20 27 62 74 2d 73 63 61 6e 27 20 7c 20 67 72 65 70 20 2d 76 20 2d 65 20 67 72 65 70 } //01 00  ps auxww | grep -iEe 'bt-scan' | grep -v -e grep
		$a_00_1 = {25 73 2f 2e 6b 64 65 34 2f 73 68 61 72 65 2f 63 6f 6e 66 69 67 } //01 00  %s/.kde4/share/config
		$a_00_2 = {2f 65 74 63 2f 68 6f 73 74 6e 61 6d 65 2d 6d 65 72 6c 69 6e } //01 00  /etc/hostname-merlin
		$a_00_3 = {25 73 2f 2e 62 61 73 68 5f 70 72 6f 66 69 6c 65 31 } //01 00  %s/.bash_profile1
		$a_00_4 = {2f 69 6e 64 65 78 2e 70 68 70 20 48 54 54 50 2f 31 2e 31 } //00 00  /index.php HTTP/1.1
	condition:
		any of ($a_*)
 
}