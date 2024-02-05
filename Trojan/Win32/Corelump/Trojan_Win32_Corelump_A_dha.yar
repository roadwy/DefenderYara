
rule Trojan_Win32_Corelump_A_dha{
	meta:
		description = "Trojan:Win32/Corelump.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_43_0 = {c9 ff 15 90 01 04 90 02 03 81 78 02 45 9e be bd 90 00 01 } //00 10 
		$a_5d_1 = {3e } //c5 85 
		$a_77_2 = {d5 e7 00 45 a3 11 57 13 00 00 5d 04 00 00 02 3e 05 80 5c 3b 00 00 04 3e 05 80 00 00 01 00 04 00 25 00 54 72 6f 6a 61 6e 44 6f 77 6e 6c 6f 61 64 65 72 3a 4f 39 37 4d 2f 55 72 73 6e 69 66 2e 50 44 41 49 21 4d 54 42 00 00 01 40 05 82 5c 00 04 00 e7 38 00 00 00 00 34 00 17 3f fc 73 bc f2 ea 8f ad a3 c7 0f 93 ec 0f 0b ac ce bc 3f d7 ac 1a 3f ea ac bc 13 80 0b ec 6a 4a 41 ad 78 89 0b d1 3f f2 c3 fe 67 d7 e3 e3 9a 12 ad 0f 14 5d 04 00 00 04 3e 05 80 5c 28 00 00 05 3e 05 80 00 00 01 00 08 00 12 00 ac 21 47 75 4c 6f 61 64 65 72 2e 42 59 47 21 4d 54 42 00 00 01 40 05 82 70 00 04 00 78 55 01 00 05 00 05 } //00 05 
	condition:
		any of ($a_*)
 
}