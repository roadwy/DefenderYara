
rule Trojan_Win64_StrelaStealer_GPAG_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.GPAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {41 0f 9c c2 45 88 d3 41 80 f3 ff 44 88 cb 44 30 db 44 20 cb 45 88 cb 41 80 f3 ff 44 88 d6 44 20 de 41 80 f2 ff 45 20 d1 44 08 ce 41 88 d9 41 20 f1 40 30 f3 41 08 d9 41 f6 c1 01 0f } //02 00 
		$a_01_1 = {00 6f 75 74 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}