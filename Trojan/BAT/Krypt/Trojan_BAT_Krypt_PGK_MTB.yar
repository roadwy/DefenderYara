
rule Trojan_BAT_Krypt_PGK_MTB{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 4a 09 61 54 09 17 62 09 1d 63 60 0d 00 11 09 17 58 13 09 11 09 06 8e 69 fe 04 13 0a 11 0a 2d d6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Krypt_PGK_MTB_2{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 08 07 06 11 08 58 93 11 06 11 08 08 58 11 07 5d 93 61 d1 9d 17 11 08 58 13 08 11 08 11 04 fe 04 2d db } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Krypt_PGK_MTB_3{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_80_0 = {54 6b 56 52 4d 56 46 55 61 33 64 4e 52 45 46 33 54 58 70 42 64 30 31 45 51 58 64 4e 52 45 45 77 54 55 52 42 64 30 31 45 51 58 64 53 61 31 70 48 } //TkVRMVFUa3dNREF3TXpBd01EQXdNREEwTURBd01EQXdSa1pH  5
	condition:
		((#a_80_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Krypt_PGK_MTB_4{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_80_0 = {56 46 68 77 54 6d 56 72 4e 55 56 55 56 45 4a 4f 5a 57 78 47 4e 6c 52 59 63 45 35 4e 56 54 45 32 56 56 68 77 54 6c 5a 46 4d 54 5a 55 57 48 42 79 } //VFhwTmVrNUVUVEJOZWxGNlRYcE5NVTE2VVhwTlZFMTZUWHBy  5
	condition:
		((#a_80_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Krypt_PGK_MTB_5{
	meta:
		description = "Trojan:BAT/Krypt.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 63 6f 6d 6d 61 6e 64 20 3d 20 5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 55 54 46 38 2e 47 65 74 53 74 72 69 6e 67 28 5b 53 79 73 74 65 6d 2e 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //3 $command = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String
		$a_01_1 = {62 6d 4e 30 61 57 39 75 49 46 52 6c 63 33 51 74 56 6b 31 33 59 58 4a 6c 49 48 73 4b 49 43 41 67 49 43 52 32 62 58 64 68 63 6d 56 54 5a 58 4a 32 61 57 4e 6c 63 79 41 39 49 45 41 6f 49 6e 5a 74 5a 47 56 69 64 57 63 69 4c 43 41 69 64 6d 31 74 62 33 56 7a 5a 53 49 73 49 43 4a 57 54 56 52 76 62 } //1 bmN0aW9uIFRlc3QtVk13YXJlIHsKICAgICR2bXdhcmVTZXJ2aWNlcyA9IEAoInZtZGVidWciLCAidm1tb3VzZSIsICJWTVRvb
		$a_01_2 = {32 78 7a 49 69 77 67 49 6c 5a 4e 54 55 56 4e 51 31 52 4d 49 69 77 67 49 6e 52 77 59 58 56 30 62 32 4e 76 62 6d 35 7a 64 6d 4d 69 4c 43 41 69 64 48 42 32 59 32 64 68 64 47 56 33 59 58 6b 69 4c 43 41 69 64 6d 31 33 59 58 4a 6c 49 69 77 67 49 6e 64 74 59 32 6b 69 4c 43 41 69 64 6d 31 34 4f 44 59 69 4b 51 } //1 2xzIiwgIlZNTUVNQ1RMIiwgInRwYXV0b2Nvbm5zdmMiLCAidHB2Y2dhdGV3YXkiLCAidm13YXJlIiwgIndtY2kiLCAidm14ODYiKQ
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}