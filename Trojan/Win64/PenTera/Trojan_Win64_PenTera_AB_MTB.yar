
rule Trojan_Win64_PenTera_AB_MTB{
	meta:
		description = "Trojan:Win64/PenTera.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 5c 24 ?? 44 0f b6 54 24 ?? 48 83 c7 03 44 89 dd 44 89 d6 41 c1 fa 02 c1 fd 04 41 c1 e3 04 41 83 e2 0f 41 89 ec 0f b6 6c 24 ?? 45 01 da c1 e6 06 41 83 e4 03 40 02 74 24 ?? 44 88 57 ?? 45 31 db 41 8d 2c ac 40 88 77 ?? 40 88 6f ?? 4c 39 cb 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}