
rule Trojan_Win64_Cobaltstrike_DQ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 63 c1 48 8d 43 01 49 2b d3 4d 03 c6 4a 8d 0c a5 ?? ?? ?? ?? 49 0f af c3 48 2b c7 49 0f af d2 48 ff c8 49 0f af cc 48 0f af c3 48 03 d0 48 8d 04 7f 48 03 d0 48 2b d6 48 03 d5 49 8d 04 ?? 0f b6 0c 01 48 8b 44 24 68 41 30 0c 01 } //1
		$a_81_1 = {4a 3e 40 59 40 4e 25 70 66 3e 28 6c 4d 4f 38 4b 21 43 4f 7a 51 6f 59 4c 32 5e 4c 29 54 3e 44 31 67 2a 24 6b 6c 24 62 4e 4d 32 6d 31 68 6b 21 2b 6d 74 4c 75 5e 2a 78 4a 6d 69 49 33 6d 50 28 6a 5a 6a 45 26 28 51 6e 64 52 23 37 } //1 J>@Y@N%pf>(lMO8K!COzQoYL2^L)T>D1g*$kl$bNM2m1hk!+mtLu^*xJmiI3mP(jZjE&(QndR#7
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}