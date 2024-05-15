
rule Trojan_BAT_Redline_GXZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {72 2e 6c 31 6e 63 30 69 6e 2e 72 75 2f 6d 61 } //r.l1nc0in.ru/ma  01 00 
		$a_01_1 = {55 00 63 00 62 00 6c 00 4c 00 74 00 6b 00 4a 00 2b 00 57 00 73 00 61 00 77 00 32 00 70 00 49 00 6b 00 38 00 58 00 76 00 45 00 4c 00 2b 00 65 00 34 00 4e 00 39 00 48 00 6b 00 51 00 69 00 46 00 2f 00 70 00 48 00 45 00 63 00 61 00 65 00 58 00 31 00 38 00 45 00 3d 00 } //01 00  UcblLtkJ+Wsaw2pIk8XvEL+e4N9HkQiF/pHEcaeX18E=
		$a_01_2 = {52 00 48 00 34 00 4e 00 73 00 76 00 4f 00 44 00 4b 00 53 00 70 00 66 00 6e 00 30 00 72 00 4e 00 5a 00 41 00 66 00 35 00 5a 00 41 00 3d 00 3d 00 } //00 00  RH4NsvODKSpfn0rNZAf5ZA==
	condition:
		any of ($a_*)
 
}