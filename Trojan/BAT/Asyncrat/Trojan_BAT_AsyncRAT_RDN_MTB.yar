
rule Trojan_BAT_AsyncRAT_RDN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 34 66 37 64 37 62 63 2d 62 63 31 37 2d 34 61 62 32 2d 61 63 30 63 2d 61 66 63 64 35 39 30 32 35 39 61 38 } //01 00  44f7d7bc-bc17-4ab2-ac0c-afcd590259a8
		$a_01_1 = {42 56 48 38 37 36 } //01 00  BVH876
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 } //01 00  aR3nbf8dQp2feLmk31
		$a_01_3 = {6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //00 00  lSfgApatkdxsVcGcrktoFd
	condition:
		any of ($a_*)
 
}