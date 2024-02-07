
rule Backdoor_Win32_Babmote_A{
	meta:
		description = "Backdoor:Win32/Babmote.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 73 79 73 74 65 6d 33 32 5c 4b 65 79 42 6f 61 72 64 41 2e 64 61 74 } //05 00  \system32\KeyBoardA.dat
		$a_01_1 = {42 61 42 79 20 52 65 4d 6f 54 65 20 47 65 74 20 56 69 64 65 6f } //03 00  BaBy ReMoTe Get Video
		$a_01_2 = {22 20 26 26 20 20 67 6f 74 6f 20 74 72 79 20 7c 7c 73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 } //00 00  " &&  goto try ||shutdown -r -t 0
	condition:
		any of ($a_*)
 
}