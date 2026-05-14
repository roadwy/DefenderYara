
rule Trojan_Win64_MaskgramStealer_PGMS_MTB{
	meta:
		description = "Trojan:Win64/MaskgramStealer.PGMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 ed 4d 63 e4 8d 50 ?? 89 c8 42 32 14 23 32 14 2b 0f af c7 83 c0 3f 41 32 04 0b 31 c2 41 88 14 0a 41 83 f9 10 75 ?? 45 31 c9 48 ff c1 41 39 c8 7f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}