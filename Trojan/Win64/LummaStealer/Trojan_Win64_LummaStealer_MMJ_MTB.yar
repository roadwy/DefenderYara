
rule Trojan_Win64_LummaStealer_MMJ_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.MMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 8a 84 04 ?? ?? ?? ?? 48 63 4c 24 7c 48 8b 54 24 40 30 04 0a 44 8b 7c 24 7c 41 83 c7 01 b8 8a 0c a5 74 8b 7c 24 3c 8b 5c 24 38 44 8b 6c 24 34 3d a5 83 70 0d 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}