
rule Trojan_Win64_Striker_AHB_MTB{
	meta:
		description = "Trojan:Win64/Striker.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 ba 43 5d 2f 61 67 65 6e 74 49 89 c4 48 89 54 24 6c 48 b8 5b 4f 42 46 53 5f 45 4e } //30
		$a_03_1 = {44 8d 42 01 41 0f af c0 89 c3 84 db 75 ?? 83 c3 ?? eb ?? 80 fb ?? 74 ?? 8d 43 e0 3c ?? 76 ?? 30 1c 16 48 ff c2 eb } //20
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}