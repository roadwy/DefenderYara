
rule Trojan_Win64_StrelaStealer_DAW_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.DAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 f1 ff 41 80 ca 01 44 20 d1 41 08 cb 80 f2 ff 41 80 f3 ff 40 80 f6 00 44 08 da 40 80 ce 00 80 f2 ff 40 20 f2 88 c1 20 d1 30 d0 08 c1 f6 c1 01 0f } //02 00 
		$a_01_1 = {41 88 c9 41 30 d1 41 20 c9 88 c1 80 f1 ff 44 88 ca 80 f2 ff 80 f3 01 41 88 ca 41 80 e2 ff 20 d8 41 88 d3 41 80 e3 ff 41 20 d9 41 08 c2 45 08 cb 45 30 da 08 d1 80 f1 ff 80 cb 01 20 d9 41 08 ca 41 f6 c2 01 0f } //01 00 
		$a_01_2 = {08 cb 30 d8 40 88 f9 80 e1 01 40 80 f7 01 40 08 f9 80 f1 ff 41 88 c1 41 30 c9 41 20 c1 88 d0 44 20 c8 44 30 ca 08 d0 a8 01 0f 85 } //01 00 
		$a_01_3 = {40 80 f7 01 41 20 f9 45 88 d6 41 80 f6 ff 41 80 e6 ff 41 20 fa 45 08 cb 45 08 d6 45 30 f3 41 88 d9 41 80 f1 ff 45 88 da 41 80 f2 ff 40 80 f6 00 44 88 cf 40 80 e7 00 40 20 f3 45 88 d6 41 80 e6 00 41 20 f3 40 08 df 45 08 de 44 30 f7 45 08 d1 41 80 f1 ff 40 80 ce 00 41 20 f1 44 08 cf 40 f6 c7 01 0f 85 } //01 00 
		$a_01_4 = {6f 75 74 2e 64 6c 6c 00 65 6e 74 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}