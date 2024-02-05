
rule Trojan_Win64_WinGO_BNK_MTB{
	meta:
		description = "Trojan:Win64/WinGO.BNK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 c7 40 08 02 00 00 00 48 8d 15 94 ea 01 00 48 89 10 48 8b 3d dc cb 49 00 48 8b 35 dd cb 49 00 48 8d 1d 07 f1 01 00 b9 06 00 00 00 31 c0 e8 82 95 f9 ff 48 8b 7c 24 50 48 89 5f 18 } //00 00 
	condition:
		any of ($a_*)
 
}