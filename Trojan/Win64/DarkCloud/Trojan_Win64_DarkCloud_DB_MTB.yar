
rule Trojan_Win64_DarkCloud_DB_MTB{
	meta:
		description = "Trojan:Win64/DarkCloud.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 43 0f b6 0c 01 01 c1 0f b6 c1 48 8b 4d b0 8a 04 01 48 63 4d f4 41 30 04 0a 8b 45 f4 83 c0 01 89 45 e0 8b 05 ?? ?? ?? ?? 8d 48 ff 0f af c8 f6 c1 01 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}