
rule Ransom_Win32_LockScreen_DM{
	meta:
		description = "Ransom:Win32/LockScreen.DM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 70 72 65 6d 69 75 6d 74 61 62 73 2e 6f 72 67 2f 63 6f 6d 62 61 74 2f 69 6e 64 65 78 2e 70 68 70 2f 61 70 69 2f 67 65 74 74 65 78 74 64 61 74 61 3f 64 61 74 61 3d 7b 25 32 32 69 64 25 32 32 3a 25 32 32 31 25 32 32 7d } //01 00  http://premiumtabs.org/combat/index.php/api/gettextdata?data={%22id%22:%221%22}
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 63 6f 6d 62 61 74 2e 74 78 74 } //00 00  C:\Windows\combat.txt
		$a_00_2 = {87 10 00 00 d5 82 c5 fd 2c 4d } //aa ff 
	condition:
		any of ($a_*)
 
}