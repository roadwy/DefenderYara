
rule Trojan_Win64_AsyncRat_CCJY_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.CCJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 83 f1 85 45 88 4c 1b ff 48 ff c0 4c 89 de 48 39 05 ad e7 0f 00 7e ?? 4c 8b 0d 9c e7 0f 00 4c 8d 5e 01 45 0f b6 0c 01 4c 39 d9 73 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}