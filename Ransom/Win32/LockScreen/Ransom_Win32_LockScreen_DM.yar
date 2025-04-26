
rule Ransom_Win32_LockScreen_DM{
	meta:
		description = "Ransom:Win32/LockScreen.DM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 70 72 65 6d 69 75 6d 74 61 62 73 2e 6f 72 67 2f 63 6f 6d 62 61 74 2f 69 6e 64 65 78 2e 70 68 70 2f 61 70 69 2f 67 65 74 74 65 78 74 64 61 74 61 3f 64 61 74 61 3d 7b 25 32 32 69 64 25 32 32 3a 25 32 32 31 25 32 32 7d } //10 http://premiumtabs.org/combat/index.php/api/gettextdata?data={%22id%22:%221%22}
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 63 6f 6d 62 61 74 2e 74 78 74 } //1 C:\Windows\combat.txt
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}