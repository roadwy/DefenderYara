
rule Trojan_BAT_MSILZilla_RDA_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 64 66 66 62 38 36 34 2d 63 65 66 34 2d 34 33 39 33 2d 61 39 31 33 2d 61 66 30 64 31 33 38 64 65 64 61 62 } //01 00  7dffb864-cef4-4393-a913-af0d138dedab
		$a_01_1 = {41 73 67 61 72 64 2d 43 72 61 63 6b } //01 00  Asgard-Crack
		$a_01_2 = {7b 72 39 65 6e 79 35 6a 72 2d 6b 77 34 7a 2d 79 68 73 6b 2d 39 30 63 63 2d 62 37 36 36 37 7a 6d 6c 73 77 31 75 7d } //01 00  {r9eny5jr-kw4z-yhsk-90cc-b7667zmlsw1u}
		$a_01_3 = {31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 61 00 30 00 38 00 36 00 65 00 30 00 65 00 66 00 62 00 61 00 64 00 36 00 35 00 66 00 30 00 62 00 62 00 2e 00 61 00 77 00 73 00 67 00 6c 00 6f 00 62 00 61 00 6c 00 61 00 63 00 63 00 65 00 6c 00 65 00 72 00 61 00 74 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00 } //00 00  127.0.0.1 a086e0efbad65f0bb.awsglobalaccelerator.com
	condition:
		any of ($a_*)
 
}