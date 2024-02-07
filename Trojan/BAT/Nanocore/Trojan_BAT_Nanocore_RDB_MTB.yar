
rule Trojan_BAT_Nanocore_RDB_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 65 66 39 61 62 66 66 2d 66 30 34 62 2d 34 64 30 61 2d 39 62 65 39 2d 30 33 39 61 65 62 64 31 31 32 64 35 } //01 00  fef9abff-f04b-4d0a-9be9-039aebd112d5
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 } //01 00  aR3nbf8dQp2feLmk31
		$a_01_2 = {6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //01 00  lSfgApatkdxsVcGcrktoFd
		$a_01_3 = {48 48 48 67 56 50 4c } //00 00  HHHgVPL
	condition:
		any of ($a_*)
 
}