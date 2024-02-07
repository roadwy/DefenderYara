
rule Trojan_BAT_RedLine_RDAJ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 39 64 65 64 37 39 31 2d 32 33 34 64 2d 34 30 65 39 2d 38 64 36 35 2d 63 33 61 38 62 37 39 36 33 33 30 36 } //01 00  f9ded791-234d-40e9-8d65-c3a8b7963306
		$a_01_1 = {53 61 66 65 48 61 6e 64 6c 65 5a 65 72 6f 4f 72 4d 69 6e 75 73 6e 76 61 6c 69 64 } //01 00  SafeHandleZeroOrMinusnvalid
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //00 00  aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd
	condition:
		any of ($a_*)
 
}