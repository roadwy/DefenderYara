
rule Ransom_Win32_LockCrypt_A_bit{
	meta:
		description = "Ransom:Win32/LockCrypt.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 5f 64 75 6b 65 6e 73 40 61 6f 6c 2e 63 6f 6d } //01 00  d_dukens@aol.com
		$a_01_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 65 6e 63 72 79 70 74 65 64 21 } //01 00  All your files have beenencrypted!
		$a_01_2 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //01 00  vssadmin delete shadows /all
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //00 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
	condition:
		any of ($a_*)
 
}