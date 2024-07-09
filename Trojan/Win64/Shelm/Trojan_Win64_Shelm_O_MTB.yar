
rule Trojan_Win64_Shelm_O_MTB{
	meta:
		description = "Trojan:Win64/Shelm.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 53 48 83 ec 38 48 8d 6c 24 30 48 8d 45 fc 49 89 c1 41 b8 40 00 00 00 ba ?? ?? ?? 00 48 8d 0d 79 0a 01 00 48 8b 05 ?? ?? 05 00 ff d0 85 c0 75 ?? 48 8b 05 ?? ?? 05 00 ff d0 89 c3 b9 02 00 00 00 48 8b 05 25 ?? 05 00 ff d0 41 89 d8 48 8d 15 29 ?? 05 00 48 89 c1 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}