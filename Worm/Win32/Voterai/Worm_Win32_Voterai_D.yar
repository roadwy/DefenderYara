
rule Worm_Win32_Voterai_D{
	meta:
		description = "Worm:Win32/Voterai.D,SIGNATURE_TYPE_PEHSTR,0d 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {56 4f 54 45 20 52 41 49 4c 41 20 4f 44 49 4e 47 41 20 46 4f 52 20 50 52 45 53 49 44 45 4e 54 20 32 30 30 37 } //01 00  VOTE RAILA ODINGA FOR PRESIDENT 2007
		$a_01_1 = {73 65 6e 64 6d 61 69 6c 2e 64 6c 6c } //01 00  sendmail.dll
		$a_01_2 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 75 74 6c 6f 6f 6b 20 45 78 70 72 65 73 73 5c 35 2e 30 5c 4d 61 69 6c } //01 00  \Software\Microsoft\Outlook Express\5.0\Mail
		$a_01_3 = {42 6f 67 75 73 20 6d 65 73 73 61 67 65 20 63 6f 64 65 20 25 64 } //00 00  Bogus message code %d
	condition:
		any of ($a_*)
 
}