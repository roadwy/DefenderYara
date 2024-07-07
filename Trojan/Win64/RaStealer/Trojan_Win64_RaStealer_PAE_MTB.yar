
rule Trojan_Win64_RaStealer_PAE_MTB{
	meta:
		description = "Trojan:Win64/RaStealer.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 2b c2 48 83 f8 02 72 90 01 01 80 f9 0d 75 90 01 06 0a 74 90 01 01 80 f9 0a 74 90 02 04 0f 85 90 01 04 80 f9 3d 75 90 02 0a 0f 87 90 01 04 80 f9 7c 90 00 } //1
		$a_03_1 = {33 c0 80 f9 40 0f 94 c0 83 e1 3f 49 90 02 03 44 2b 90 01 01 41 8b 90 01 01 44 8b 90 01 01 c1 e0 06 44 0b 90 01 01 49 83 fb 04 75 90 01 01 45 33 db 45 85 90 01 01 74 90 01 01 41 8b 90 01 01 c1 e8 10 88 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}