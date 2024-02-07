
rule Worm_Win32_Pushbot_VJ{
	meta:
		description = "Worm:Win32/Pushbot.VJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {26 6d 73 67 5f 74 65 78 74 3d 25 73 26 74 6f 5f 6f 66 66 6c 69 6e 65 3d 66 61 6c 73 65 26 70 6f 73 74 5f 66 6f 72 6d 5f 69 64 3d } //01 00  &msg_text=%s&to_offline=false&post_form_id=
		$a_03_1 = {6a 00 6a 03 6a 2d 6a 11 ff 15 90 01 04 6a 00 6a 00 6a 00 6a 0d ff 15 90 1b 00 8b 85 90 01 02 ff ff 8b 08 8b 95 90 1b 02 ff ff 52 ff 51 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}