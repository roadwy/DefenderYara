
rule Backdoor_Linux_Dockster_A{
	meta:
		description = "Backdoor:Linux/Dockster.A,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 6d 61 63 2e 44 6f 63 6b 73 65 74 } //01 00  ~/Library/LaunchAgents/mac.Dockset
		$a_01_1 = {2e 2f 2e 44 6f 63 6b 73 65 74 20 20 6b 65 79 } //01 00  ./.Dockset  key
		$a_01_2 = {2f 6d 61 63 2e 44 6f 63 6b 73 65 74 2e 64 65 6d 61 6e 2e 70 6c 69 73 74 } //01 00  /mac.Dockset.deman.plist
		$a_01_3 = {2f 73 62 69 6e 2f 69 66 63 6f 6e 66 69 67 20 65 6e 30 20 65 74 68 65 72 20 7c 67 72 65 70 20 65 74 68 65 72 } //01 00  /sbin/ifconfig en0 ether |grep ether
		$a_03_4 = {2f 76 61 72 2f 74 6d 70 2f 90 02 15 2e 6c 63 6b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}