
rule Trojan_Win32_Zlob_gen_R{
	meta:
		description = "Trojan:Win32/Zlob.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 58 4f 62 6a 65 63 74 2e 43 68 6c 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 56 69 64 65 6f 20 41 63 74 69 76 65 58 20 4f 62 6a 65 63 74 00 } //01 00  塁扏敪瑣䌮汨匀景睴牡履楍牣獯景屴楗摮睯屳畃牲湥噴牥楳湯啜楮獮慴汬噜摩潥䄠瑣癩塥传橢捥t
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 5c 49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 00 } //01 00  潓瑦慷敲屜湉整湲瑥匠捥牵瑩y
		$a_00_2 = {50 6c 65 61 73 65 20 72 65 62 6f 6f 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 74 6f 20 63 6f 6d 70 6c 65 74 65 20 75 6e 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 20 70 72 6f 63 65 73 73 2e 20 52 65 62 6f 6f 74 20 6e 6f 77 3f } //01 00  Please reboot your computer to complete uninstallation process. Reboot now?
		$a_00_3 = {44 65 6c 65 74 65 20 6f 6e 20 72 65 62 6f 6f 74 3a 20 } //00 00  Delete on reboot: 
	condition:
		any of ($a_*)
 
}