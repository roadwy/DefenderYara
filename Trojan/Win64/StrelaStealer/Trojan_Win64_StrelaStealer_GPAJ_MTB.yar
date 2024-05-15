
rule Trojan_Win64_StrelaStealer_GPAJ_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {41 80 f2 ff 45 20 d1 44 08 ce 41 88 d9 41 80 f1 ff 41 88 f2 41 80 f2 ff 41 b3 01 41 80 f3 01 44 88 cf 40 80 e7 ff 44 20 db 45 88 d6 41 80 e6 ff 44 20 de 40 08 df 41 08 f6 44 30 f7 45 08 d1 41 80 f1 ff 41 80 cb 01 45 20 d9 44 08 } //05 00 
		$a_01_1 = {83 e0 01 83 f8 00 41 0f 94 c1 83 fa 0a 41 0f 9c c2 45 88 cb 41 80 f3 ff 41 80 e3 01 b3 01 40 88 de 40 80 f6 01 44 88 cf 40 20 f7 41 88 de 41 80 f6 01 41 80 e6 ff 40 80 e6 01 41 08 fb 41 08 f6 45 30 f3 44 88 d6 40 80 f6 ff 40 80 } //05 00 
		$a_01_2 = {80 f3 ff 80 e3 00 40 b6 01 40 88 f7 40 80 f7 00 45 88 d6 41 20 fe 41 88 f7 41 80 f7 01 41 80 e7 00 40 80 e7 01 44 08 f3 41 08 ff 44 30 fb 44 88 df 40 80 f7 ff 40 80 e7 01 41 88 f6 41 80 f6 01 45 88 df 45 20 f7 44 08 ff 41 88 } //00 00 
	condition:
		any of ($a_*)
 
}