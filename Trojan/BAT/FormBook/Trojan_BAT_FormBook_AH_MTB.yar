
rule Trojan_BAT_FormBook_AH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {57 9d a2 29 09 1f 90 01 0a 02 90 01 03 bf 90 01 03 3a 90 01 03 b2 90 00 } //03 00 
		$a_80_1 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //get_Password  03 00 
		$a_80_2 = {44 65 6c 65 67 61 74 65 41 73 79 6e 63 53 74 61 74 65 } //DelegateAsyncState  03 00 
		$a_80_3 = {45 6d 61 69 6c 4c 61 62 65 6c } //EmailLabel  03 00 
		$a_80_4 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FormBook_AH_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 11 08 72 35 00 00 70 28 90 01 03 0a 72 53 00 00 70 20 00 01 00 00 14 14 18 8d 12 00 00 01 25 16 06 11 08 9a a2 25 17 1f 10 8c 7f 00 00 01 a2 90 00 } //01 00 
		$a_01_1 = {41 00 43 00 5f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //01 00  AC_Control
		$a_01_2 = {50 00 23 00 65 00 73 00 2e 00 57 00 68 00 23 00 74 00 65 00 } //01 00  P#es.Wh#te
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_4 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //00 00  System.Convert
	condition:
		any of ($a_*)
 
}