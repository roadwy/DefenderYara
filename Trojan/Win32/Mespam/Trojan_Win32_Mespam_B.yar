
rule Trojan_Win32_Mespam_B{
	meta:
		description = "Trojan:Win32/Mespam.B,SIGNATURE_TYPE_PEHSTR,0e 00 0c 00 11 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 61 62 62 65 72 45 6e 67 69 6e 65 } //01 00  JabberEngine
		$a_01_1 = {4d 45 53 53 41 47 45 20 57 49 54 48 20 41 44 56 20 54 45 58 54 20 53 45 4e 44 45 44 } //01 00  MESSAGE WITH ADV TEXT SENDED
		$a_01_2 = {62 6f 64 79 20 6f 6b } //01 00  body ok
		$a_01_3 = {73 73 61 67 65 20 74 6f 3d 22 } //01 00  ssage to="
		$a_01_4 = {50 61 63 6b 65 74 20 6c 65 6e 20 3e } //01 00  Packet len >
		$a_01_5 = {50 61 63 6b 65 74 20 46 72 6f 6d 20 75 73 65 72 } //01 00  Packet From user
		$a_01_6 = {7a 75 32 2f 7a 63 2e 70 68 70 } //01 00  zu2/zc.php
		$a_01_7 = {3f 6c 3d 25 73 26 64 3d 25 73 26 76 3d 25 73 } //01 00  ?l=%s&d=%s&v=%s
		$a_01_8 = {73 6d 74 73 70 6d } //01 00  smtspm
		$a_01_9 = {45 52 54 20 54 45 58 54 20 74 6f 3a } //01 00  ERT TEXT to:
		$a_01_10 = {26 6d 73 67 5f 62 6f 64 79 3d } //01 00  &msg_body=
		$a_01_11 = {2f 6e 65 77 74 68 72 65 61 64 2e 70 68 70 3f 64 6f 3d 70 6f 73 74 74 68 72 65 61 64 } //01 00  /newthread.php?do=postthread
		$a_01_12 = {69 3f 6d 6f 64 65 3d 63 6f 6d 70 6f 73 65 } //01 00  i?mode=compose
		$a_01_13 = {43 4f 4e 54 41 43 54 20 54 4f 3a 3a 3a 3a 3e 3e 3e } //01 00  CONTACT TO::::>>>
		$a_01_14 = {72 76 7a 31 3d 25 64 26 72 76 7a 32 3d 25 } //01 00  rvz1=%d&rvz2=%
		$a_01_15 = {26 66 6c 64 42 6f 64 79 3d } //01 00  &fldBody=
		$a_01_16 = {68 74 6d 6c 63 6f 6d 70 6f 73 65 2f 63 5f 63 6f 6d 70 6f 73 65 } //00 00  htmlcompose/c_compose
	condition:
		any of ($a_*)
 
}