
rule Trojan_Win64_Lazy_AHN_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 30 48 c1 e0 ?? 48 c1 e9 ?? 48 33 c8 48 8b 44 24 30 48 33 c1 48 89 44 24 30 48 8b 44 24 30 48 8b 4c 24 30 } //30
		$a_01_1 = {48 8b 4c 24 30 49 03 ca 48 03 ca 48 89 4c 24 30 48 8b 44 24 30 49 0f af c0 49 03 c1 } //20
		$a_01_2 = {64 69 74 6d 65 63 68 69 6e 61 } //10 ditmechina
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}