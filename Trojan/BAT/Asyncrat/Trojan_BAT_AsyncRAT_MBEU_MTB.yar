
rule Trojan_BAT_AsyncRAT_MBEU_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 6a 66 64 66 68 66 67 66 61 64 66 66 64 64 63 64 66 66 66 66 73 6b 68 6a } //01 00  hjfdfhfgfadffddcdffffskhj
		$a_01_1 = {73 67 66 68 6a 66 66 66 66 67 64 72 66 68 64 66 64 66 68 66 66 61 64 66 73 66 73 73 63 66 67 64 62 } //01 00  sgfhjffffgdrfhdfdfhffadfsfsscfgdb
		$a_01_2 = {67 64 66 67 64 32 64 66 73 66 76 66 67 64 66 64 6a } //01 00  gdfgd2dfsfvfgdfdj
		$a_01_3 = {66 67 68 68 66 67 73 66 66 72 66 64 66 64 66 66 66 64 66 64 73 68 66 64 73 64 66 68 } //01 00  fghhfgsffrfdfdfffdfdshfdsdfh
		$a_01_4 = {63 66 66 66 64 61 64 66 64 72 73 66 73 73 68 64 6b 66 66 66 67 68 } //01 00  cfffdadfdrsfsshdkfffgh
		$a_01_5 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}