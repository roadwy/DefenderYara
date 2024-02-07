
rule Trojan_Win64_Cobaltstrike_DS_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {46 0f b6 0c 00 44 33 c9 44 8b 05 90 01 04 44 0f af 05 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 8b 0d 90 01 04 8b 44 24 90 01 01 2b c1 03 05 90 01 04 8b 0d 90 01 04 03 c8 8b c2 03 c1 8b 0d 90 01 04 03 c8 41 8b c0 03 c1 03 05 90 01 04 2b 05 90 01 04 2b 05 90 01 04 03 05 90 01 04 8b c8 48 8b 44 24 90 01 01 44 88 0c 08 90 00 } //01 00 
		$a_81_1 = {55 3e 40 3f 78 6d 36 50 24 36 71 6f 4c 5f 51 53 44 48 64 6f 56 6e 6f 4f 63 41 4c 43 58 58 7a 26 4c 36 6e 45 67 71 23 76 33 25 35 57 24 30 4a 52 2b 46 40 79 46 3f 63 49 5e 72 32 70 26 7a 2a 62 51 2a 6e 25 66 43 44 6e 25 45 61 35 34 38 29 25 3f 44 } //00 00  U>@?xm6P$6qoL_QSDHdoVnoOcALCXXz&L6nEgq#v3%5W$0JR+F@yF?cI^r2p&z*bQ*n%fCDn%Ea548)%?D
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_DS_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 13 49 8b c8 f6 d2 4c 3b c7 73 17 0f 1f 00 0f b6 c1 40 2a c6 32 01 32 c2 88 01 49 03 cb 48 3b cf 72 ec 49 ff c0 48 ff c3 49 83 ea 01 75 d0 } //00 00 
	condition:
		any of ($a_*)
 
}