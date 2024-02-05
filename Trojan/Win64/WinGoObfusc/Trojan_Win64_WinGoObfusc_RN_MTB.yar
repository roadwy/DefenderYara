
rule Trojan_Win64_WinGoObfusc_RN_MTB{
	meta:
		description = "Trojan:Win64/WinGoObfusc.RN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 2d 0b 08 00 00 48 8d be 00 f0 ff ff bb 00 10 00 00 50 49 89 e1 41 b8 04 00 00 00 48 89 da 48 89 f9 48 83 ec 20 ff d5 48 8d 87 af 01 00 00 80 20 7f 80 60 28 7f 4c 8d 4c 24 20 4d 8b 01 48 89 da 48 89 f9 ff d5 } //00 00 
	condition:
		any of ($a_*)
 
}