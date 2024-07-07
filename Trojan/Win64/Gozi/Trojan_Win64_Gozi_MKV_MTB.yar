
rule Trojan_Win64_Gozi_MKV_MTB{
	meta:
		description = "Trojan:Win64/Gozi.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ff 41 89 cb 42 8d 04 0a 8b 15 90 01 04 2b 05 90 01 04 45 0f af d9 44 0f af 1d 90 01 04 0f af d1 0f af 0d 90 01 04 29 d0 48 8d 15 99 39 00 00 0f af 0d 90 01 04 44 29 d8 41 0f af c9 44 0f af 0d 87 29 00 00 01 c8 44 29 c8 2b 05 90 01 04 48 98 8a 04 02 48 8b 54 24 90 01 01 42 32 04 12 42 88 04 16 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}