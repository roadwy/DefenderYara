
rule Trojan_Win64_LummaStealer_BOE_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 8a 84 04 ?? ?? ?? ?? 48 63 4c 24 64 48 8b 54 24 30 30 04 0a 8b 7c 24 64 83 c7 01 b8 5b b4 35 56 41 bf 4f aa 0b 2b 41 bd 46 5b d6 f4 8b 6c 24 2c 3d 14 16 d6 0b 0f 8e } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}