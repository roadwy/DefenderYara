
rule Trojan_BAT_DCRat_DEN_MTB{
	meta:
		description = "Trojan:BAT/DCRat.DEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_81_0 = {5c 64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //03 00  \discord\Local Storage\leveldb
		$a_81_1 = {4f 6e 53 74 65 61 6c 65 72 44 6f 6e 65 } //03 00  OnStealerDone
		$a_81_2 = {57 6f 72 6b 2e 6c 6f 67 } //03 00  Work.log
		$a_81_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 46 69 72 65 77 61 6c 6c 50 72 6f 64 75 63 74 } //03 00  SELECT * FROM FirewallProduct
		$a_81_4 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d 31 30 30 30 39 2d 31 31 31 31 32 7d } //03 00  {11111-22222-10009-11112}
		$a_81_5 = {5a 47 4b 69 48 73 6c 47 50 6f 36 76 57 6e 49 6a 61 6c 2e 79 39 4c 79 6c 45 61 53 63 74 33 72 53 66 65 72 56 30 } //03 00  ZGKiHslGPo6vWnIjal.y9LylEaSct3rSferV0
		$a_81_6 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d 35 30 30 30 31 2d 30 30 30 30 30 7d } //03 00  {11111-22222-50001-00000}
		$a_81_7 = {72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 } //00 00  root\SecurityCenter
	condition:
		any of ($a_*)
 
}