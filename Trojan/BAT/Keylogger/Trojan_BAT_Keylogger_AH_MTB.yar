
rule Trojan_BAT_Keylogger_AH_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0a 00 00 03 00 "
		
	strings :
		$a_80_0 = {5b 50 61 67 65 20 44 6f 77 6e 5d } //[Page Down]  03 00 
		$a_80_1 = {5b 48 6f 6d 65 5d } //[Home]  03 00 
		$a_80_2 = {5b 49 6e 73 65 72 74 5d } //[Insert]  03 00 
		$a_80_3 = {5b 45 6e 64 5d } //[End]  03 00 
		$a_80_4 = {5b 45 73 63 5d } //[Esc]  03 00 
		$a_80_5 = {43 6c 69 70 62 6f 61 72 64 50 72 6f 78 79 } //ClipboardProxy  03 00 
		$a_80_6 = {59 6f 75 72 20 50 6f 6c 79 6d 6f 72 70 68 69 63 20 4b 65 79 6c 6f 67 67 65 72 20 68 61 73 20 62 65 65 6e 20 61 63 74 69 76 61 74 65 64 20 6f 6e } //Your Polymorphic Keylogger has been activated on  03 00 
		$a_80_7 = {5c 57 69 6e 64 6f 77 73 20 46 69 72 65 77 61 6c 6c 5c 63 6f 6e 66 69 67 5c } //\Windows Firewall\config\  03 00 
		$a_80_8 = {44 69 73 61 62 6c 65 53 52 } //DisableSR  03 00 
		$a_80_9 = {67 65 74 5f 50 72 69 6d 61 72 79 53 63 72 65 65 6e } //get_PrimaryScreen  00 00 
	condition:
		any of ($a_*)
 
}