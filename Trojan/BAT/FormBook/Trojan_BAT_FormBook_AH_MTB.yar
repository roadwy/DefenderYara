
rule Trojan_BAT_FormBook_AH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {57 9d a2 29 09 1f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 ?? ?? ?? bf ?? ?? ?? 3a ?? ?? ?? b2 } //10
		$a_80_1 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //get_Password  3
		$a_80_2 = {44 65 6c 65 67 61 74 65 41 73 79 6e 63 53 74 61 74 65 } //DelegateAsyncState  3
		$a_80_3 = {45 6d 61 69 6c 4c 61 62 65 6c } //EmailLabel  3
		$a_80_4 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}
rule Trojan_BAT_FormBook_AH_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 72 35 00 00 70 28 ?? ?? ?? 0a 72 53 00 00 70 20 00 01 00 00 14 14 18 8d 12 00 00 01 25 16 06 11 08 9a a2 25 17 1f 10 8c 7f 00 00 01 a2 } //2
		$a_01_1 = {41 00 43 00 5f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //1 AC_Control
		$a_01_2 = {50 00 23 00 65 00 73 00 2e 00 57 00 68 00 23 00 74 00 65 00 } //1 P#es.Wh#te
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_4 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 } //1 System.Convert
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}