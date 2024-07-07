
rule Trojan_Win32_Qakbot_CJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {49 6c 5f 64 69 72 65 63 74 6f 72 79 5f 63 6f 6d 70 6c 65 74 69 6f 6e 5f 68 6f 6f 6b } //1 Il_directory_completion_hook
		$a_01_1 = {49 69 5f 6d 6f 76 65 6d 65 6e 74 5f 6b 65 79 6d 61 70 } //1 Ii_movement_keymap
		$a_01_2 = {49 72 6c 5f 61 64 64 5f 65 78 65 63 75 74 69 6e 67 5f 6b 65 79 73 65 71 } //1 Irl_add_executing_keyseq
		$a_01_3 = {49 72 6c 5f 62 72 61 63 6b 65 74 65 64 5f 72 65 61 64 5f 6d 62 73 74 72 69 6e 67 } //1 Irl_bracketed_read_mbstring
		$a_01_4 = {49 72 6c 5f 76 69 5f 64 6f 6d 6f 76 65 5f 6d 6f 74 69 6f 6e 5f 63 6c 65 61 6e 75 70 } //1 Irl_vi_domove_motion_cleanup
		$a_01_5 = {49 6f 70 79 5f 68 69 73 74 6f 72 79 5f 65 6e 74 72 79 } //1 Iopy_history_entry
		$a_01_6 = {49 69 73 74 6f 72 79 5f 71 75 6f 74 65 73 5f 69 6e 68 69 62 69 74 5f 65 78 70 61 6e 73 69 6f 6e } //1 Iistory_quotes_inhibit_expansion
		$a_01_7 = {49 6c 5f 63 61 6c 6c 5f 6c 61 73 74 5f 6b 62 64 5f 6d 61 63 72 6f } //1 Il_call_last_kbd_macro
		$a_01_8 = {49 6c 5f 63 6f 6d 70 6c 65 74 69 6f 6e 5f 77 6f 72 64 5f 62 72 65 61 6b 5f 68 6f 6f 6b } //1 Il_completion_word_break_hook
		$a_01_9 = {49 69 6c 64 65 5f 65 78 70 61 6e 73 69 6f 6e 5f 70 72 65 65 78 70 61 6e 73 69 6f 6e 5f 68 6f 6f 6b } //1 Iilde_expansion_preexpansion_hook
		$a_01_10 = {49 68 5f 75 6e 73 65 74 5f 6e 6f 64 65 6c 61 79 5f 6d 6f 64 65 } //1 Ih_unset_nodelay_mode
		$a_01_11 = {49 6c 5f 73 65 74 5f 70 61 72 65 6e 5f 62 6c 69 6e 6b 5f 74 69 6d 65 6f 75 74 } //1 Il_set_paren_blink_timeout
		$a_01_12 = {4e 69 6b 6e } //1 Nikn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}