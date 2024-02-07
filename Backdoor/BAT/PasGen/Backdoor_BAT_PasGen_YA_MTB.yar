
rule Backdoor_BAT_PasGen_YA_MTB{
	meta:
		description = "Backdoor:BAT/PasGen.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 61 00 70 00 69 00 5f 00 70 00 6f 00 73 00 74 00 2e 00 70 00 68 00 70 00 } //01 00  ://pastebin.com/api/api_post.php
		$a_01_1 = {3a 00 2f 00 2f 00 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2e 00 70 00 68 00 70 00 } //01 00  ://pastebin.com/raw.php
		$a_01_2 = {69 00 73 00 44 00 69 00 76 00 69 00 6e 00 67 00 } //01 00  isDiving
		$a_01_3 = {69 00 73 00 53 00 68 00 6f 00 6f 00 74 00 69 00 6e 00 67 00 } //01 00  isShooting
		$a_01_4 = {73 00 65 00 74 00 50 00 6c 00 61 00 79 00 65 00 72 00 44 00 65 00 61 00 64 00 } //00 00  setPlayerDead
	condition:
		any of ($a_*)
 
}