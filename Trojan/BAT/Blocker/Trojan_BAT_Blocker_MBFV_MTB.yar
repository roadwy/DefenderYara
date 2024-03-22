
rule Trojan_BAT_Blocker_MBFV_MTB{
	meta:
		description = "Trojan:BAT/Blocker.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f } //01 00 
		$a_01_1 = {4c 00 2e 00 6f 00 2e 00 61 00 2e 00 64 00 2e 00 00 27 } //01 00  L.o.a.d.✀
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 } //00 00  CreateDecrypt
	condition:
		any of ($a_*)
 
}